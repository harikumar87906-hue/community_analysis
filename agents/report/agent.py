"""
Report Agent — core agent class that orchestrates report generation.

Receives results from Threat Analyzer Agent and Community Agent,
computes combined risk scores, generates an executive summary and
recommendations via Ollama (llama3.2), stores the full report in
MongoDB, and prints a formatted CLI report.
"""

import json
import uuid
from datetime import datetime, timezone

from .config import log
from .llm import call_llama, fallback_executive_summary, fallback_recommendations
from .risk import compute_combined_risk
from .storage import store_report
from .printer import print_report


class ReportAgent:
    """
    Final agent in the InsightGraph pipeline.
    Aggregates Threat Analyzer + Community Agent results into a unified report.
    """

    def run(
        self,
        threat_results: list[dict],
        threat_summary: dict,
        propagation_results: dict,
    ) -> dict:
        """
        Build the full report from upstream agent results.

        Args:
            threat_results:      List of per-post threat dicts from Threat Analyzer Agent.
            threat_summary:      Aggregated threat stats from Threat Analyzer Agent.
            propagation_results: Propagation/community analysis from Community Agent.

        Returns:
            Full report dict (also saved to MongoDB and printed to CLI).
        """
        log.info("Report Agent started")

        # ── Step 1: Combined risk per subreddit ──
        log.info("Step 1 — Computing combined risk scores per subreddit")
        combined_risk = compute_combined_risk(threat_results, propagation_results)
        log.info(f"  Computed risk for {len(combined_risk)} subreddit(s)")

        # ── Step 2: Build structured report dict ──
        log.info("Step 2 — Building structured report")

        # Top 5 threats by threat_score
        top_threats = sorted(
            [t for t in threat_results if t.get("severity") != "CLEAN"],
            key=lambda x: x.get("threat_score", 0),
            reverse=True,
        )[:5]

        # Key actors — combine top amplifiers + top bridges
        key_actors = []
        for amp in propagation_results.get("top_amplifiers", []):
            key_actors.append({
                "username": amp.get("username", "?"),
                "role":     "Amplifier",
                "score":    amp.get("propagation_score", 0),
                "details":  f"out_degree={amp.get('out_degree', 0)}, subs={amp.get('subreddits', [])}",
            })
        for bridge in propagation_results.get("top_bridges", []):
            key_actors.append({
                "username": bridge.get("username", "?"),
                "role":     "Bridge",
                "score":    bridge.get("betweenness", 0),
                "details":  f"connects={bridge.get('connects', [])}",
            })
        key_actors.sort(key=lambda x: x["score"], reverse=True)

        # All unique IOCs
        ioc_list = list(set(
            ioc
            for t in threat_results
            for ioc in t.get("iocs", [])
            if ioc
        ))
        ioc_list.sort()

        report = {
            "report_id":                  str(uuid.uuid4()),
            "generated_at":               datetime.now(timezone.utc).isoformat(),
            "executive_summary":          "",        # filled in Step 3
            "threat_summary":             threat_summary,
            "propagation_summary":        propagation_results,
            "combined_risk_by_subreddit": combined_risk,
            "top_threats":                top_threats,
            "key_actors":                 key_actors,
            "ioc_list":                   ioc_list,
            "recommendations":           [],        # filled in Step 3
            "analyzed_at":                datetime.now(timezone.utc).isoformat(),
        }

        # ── Step 3: LLM call via Ollama ──
        log.info("Step 3 — Generating executive summary and recommendations via Ollama")

        # Build prompts
        summary_prompt = (
            "You are a cybersecurity analyst. Based on the following threat intelligence data, "
            "write an executive summary in exactly 3 sentences. Use plain English, no jargon.\n\n"
            f"Total posts analyzed: {threat_summary.get('total_analyzed', 0)}\n"
            f"Threats found: {threat_summary.get('total_threats', 0)}\n"
            f"Severity breakdown: {json.dumps(threat_summary.get('by_severity', {}))}\n"
            f"Threat types: {json.dumps(threat_summary.get('by_type', {}))}\n"
            f"Top IOCs: {threat_summary.get('top_iocs', [])}\n"
            f"Propagation — users: {propagation_results.get('total_users', 0)}, "
            f"amplifiers: {propagation_results.get('role_distribution', {}).get('Amplifier', 0)}, "
            f"bridges: {propagation_results.get('role_distribution', {}).get('Bridge', 0)}\n"
            f"Cascade depth max: {propagation_results.get('cascade_depth', {}).get('max', 0)}\n\n"
            "Write exactly 3 sentences. No bullet points. No headings."
        )

        rec_prompt = (
            "You are a cybersecurity analyst. Based on the following threat data, "
            "provide exactly 3 actionable recommendations as bullet points.\n\n"
            f"Top threat type: {max(threat_summary.get('by_type', {'unknown': 0}).items(), key=lambda x: x[1], default=('unknown', 0))[0]}\n"
            f"Critical threats: {threat_summary.get('by_severity', {}).get('CRITICAL', 0)}\n"
            f"High threats: {threat_summary.get('by_severity', {}).get('HIGH', 0)}\n"
            f"IOCs found: {ioc_list[:5]}\n"
            f"Top amplifier accounts: {[a.get('username') for a in propagation_results.get('top_amplifiers', [])[:3]]}\n"
            f"Affected subreddits: {propagation_results.get('most_affected_subreddits', [])}\n\n"
            "Provide exactly 3 bullet points. Each must be specific and actionable. "
            "Start each with a dash (-). No introductory text."
        )

        # Call Ollama for executive summary
        exec_summary = call_llama(summary_prompt)
        if exec_summary:
            report["executive_summary"] = exec_summary
            log.info("  Executive summary generated via Ollama")
        else:
            report["executive_summary"] = fallback_executive_summary(threat_summary, propagation_results)
            log.info("  Executive summary generated via fallback (rule-based)")

        # Call Ollama for recommendations
        rec_text = call_llama(rec_prompt)
        if rec_text:
            # Parse bullet points from LLM response
            recs = [
                line.strip().lstrip("-•").strip()
                for line in rec_text.split("\n")
                if line.strip() and line.strip()[0] in "-•0123456789"
            ]
            # If parsing failed, try splitting by numbered lines
            if not recs:
                recs = [line.strip() for line in rec_text.split("\n") if line.strip()]
            report["recommendations"] = recs[:3]
            log.info("  Recommendations generated via Ollama")
        else:
            report["recommendations"] = fallback_recommendations(threat_summary, propagation_results)
            log.info("  Recommendations generated via fallback (rule-based)")

        # ── Step 4: Save to MongoDB ──
        log.info("Step 4 — Saving report to MongoDB")
        store_report(report)

        # ── Step 5: Print CLI report ──
        log.info("Step 5 — Printing report to CLI")
        print_report(report)

        log.info("Report Agent complete")
        return report
