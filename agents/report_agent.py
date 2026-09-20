"""
report_agent.py — Report Generation Agent for InsightGraph

Final agent in the pipeline. Receives results from STIA Agent and
Community Agent, computes combined risk scores, generates an
executive summary and recommendations via Ollama (llama3.2),
stores the full report in MongoDB, and prints a formatted CLI report.

Run directly with mock data:
    python agents/report_agent.py
"""

import os
import sys
import json
import uuid
import logging
import warnings
from collections import Counter
from datetime import datetime, timezone

# Fix Windows terminal encoding for Unicode output
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8")

import requests
from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [REPORT] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("report_agent")

# ── MongoDB config (from .env) ────────────────────────────────────────────────
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB  = os.getenv("MONGO_DB", "insightgraph")

# ── Ollama config ─────────────────────────────────────────────────────────────
OLLAMA_URL   = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "deepseek-r1:8b")

# ── Severity colors for terminal output ───────────────────────────────────────
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "LOW":      "\033[92m",   # green
    "CLEAN":    "\033[92m",   # green
}
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"


# ══════════════════════════════════════════════════════════════════════════════
# Ollama LLM helper
# ══════════════════════════════════════════════════════════════════════════════

def call_llama(prompt: str) -> str:
    """
    Call Ollama REST API for text generation.
    Returns generated text or empty string on failure.
    """
    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model":  OLLAMA_MODEL,
                "prompt": prompt,
                "stream": False,
            },
            timeout=120,
        )
        if response.status_code == 200:
            return response.json().get("response", "").strip()
        else:
            log.warning(f"Ollama returned status {response.status_code}")
            return ""
    except requests.ConnectionError:
        log.warning("Ollama is not running — falling back to rule-based summary")
        return ""
    except requests.Timeout:
        log.warning("Ollama request timed out — falling back to rule-based summary")
        return ""
    except Exception as e:
        log.warning(f"Ollama call failed: {e} — falling back to rule-based summary")
        return ""


# ══════════════════════════════════════════════════════════════════════════════
# Fallback rule-based generators
# ══════════════════════════════════════════════════════════════════════════════

def _fallback_executive_summary(threat_summary: dict, propagation_results: dict) -> str:
    """Generate a rule-based executive summary when Ollama is unavailable."""
    total      = threat_summary.get("total_analyzed", 0)
    threats    = threat_summary.get("total_threats", 0)
    critical   = threat_summary.get("by_severity", {}).get("CRITICAL", 0)
    high       = threat_summary.get("by_severity", {}).get("HIGH", 0)
    top_type   = max(threat_summary.get("by_type", {"unknown": 0}).items(), key=lambda x: x[1], default=("unknown", 0))
    amplifiers = propagation_results.get("role_distribution", {}).get("Amplifier", 0)

    severity_word = "critical" if critical > 0 else "significant" if high > 0 else "moderate"

    return (
        f"Analysis of {total} posts identified {threats} threats, "
        f"including {critical} critical and {high} high-severity incidents. "
        f"{top_type[0]} was the most prevalent threat type with {top_type[1]} occurrences. "
        f"{amplifiers} amplifier accounts were detected actively spreading content across subreddits, "
        f"indicating {severity_word} coordinated threat activity."
    )


def _fallback_recommendations(threat_summary: dict, propagation_results: dict) -> list[str]:
    """Generate rule-based recommendations when Ollama is unavailable."""
    recommendations = []
    by_type    = threat_summary.get("by_type", {})
    by_sev     = threat_summary.get("by_severity", {})
    top_amps   = propagation_results.get("top_amplifiers", [])
    iocs       = threat_summary.get("top_iocs", [])

    # Recommendation 1 — based on top threat type
    top_type = max(by_type.items(), key=lambda x: x[1], default=("threats", 0))
    recommendations.append(
        f"Prioritize monitoring for {top_type[0]} attacks — {top_type[1]} instances detected. "
        f"Deploy targeted content filters for this threat category."
    )

    # Recommendation 2 — based on amplifiers/propagation
    if top_amps:
        amp_names = ", ".join(a.get("username", "unknown") for a in top_amps[:3])
        recommendations.append(
            f"Investigate high-influence amplifier accounts ({amp_names}) for potential "
            f"coordinated inauthentic behavior and escalate to platform trust & safety."
        )
    else:
        recommendations.append(
            "Monitor user interaction patterns for emerging amplifier accounts "
            "that could facilitate rapid threat propagation across subreddits."
        )

    # Recommendation 3 — based on IOCs
    if iocs:
        ioc_str = ", ".join(iocs[:3])
        recommendations.append(
            f"Block or flag the following suspicious domains: {ioc_str}. "
            f"Add to threat intelligence feeds and URL blocklists."
        )
    elif by_sev.get("CRITICAL", 0) > 0:
        recommendations.append(
            f"Immediately review the {by_sev['CRITICAL']} critical-severity posts "
            f"for active phishing or malware campaigns requiring urgent takedown."
        )
    else:
        recommendations.append(
            "Establish automated URL scanning for newly posted links to detect "
            "emerging phishing and malware distribution domains."
        )

    return recommendations


# ══════════════════════════════════════════════════════════════════════════════
# Combined risk scoring
# ══════════════════════════════════════════════════════════════════════════════

def _compute_combined_risk(threat_results: list[dict], propagation_results: dict) -> dict:
    """
    Compute combined risk score per subreddit.
    Formula: combined_risk = (avg_threat_score * 0.6) + (propagation_influence * 0.4)
    """
    # Aggregate threat scores by subreddit
    sub_threat_scores = {}
    sub_threat_counts = {}
    for t in threat_results:
        sub = t.get("subreddit", "unknown")
        score = t.get("threat_score", 0)
        sub_threat_scores[sub] = sub_threat_scores.get(sub, 0) + score
        sub_threat_counts[sub] = sub_threat_counts.get(sub, 0) + 1

    # Compute average threat score per subreddit
    sub_avg_threat = {}
    for sub in sub_threat_scores:
        count = sub_threat_counts.get(sub, 1)
        sub_avg_threat[sub] = sub_threat_scores[sub] / max(count, 1)

    # Get propagation influence per subreddit from top amplifiers
    sub_propagation = {}
    top_amplifiers = propagation_results.get("top_amplifiers", [])
    for amp in top_amplifiers:
        prop_score = amp.get("propagation_score", 0)
        for sub in amp.get("subreddits", []):
            sub_propagation[sub] = max(sub_propagation.get(sub, 0), prop_score)

    # Combine all subreddits
    all_subs = set(sub_avg_threat.keys()) | set(sub_propagation.keys())

    combined = {}
    for sub in all_subs:
        threat_part = sub_avg_threat.get(sub, 0) * 0.6
        prop_part   = sub_propagation.get(sub, 0) * 0.4
        risk_score  = round(threat_part + prop_part, 2)

        if risk_score >= 80:
            risk_label = "CRITICAL"
        elif risk_score >= 55:
            risk_label = "HIGH"
        elif risk_score >= 30:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"

        combined[sub] = {
            "risk_score":       risk_score,
            "risk_label":       risk_label,
            "avg_threat_score": round(sub_avg_threat.get(sub, 0), 2),
            "propagation_score": round(sub_propagation.get(sub, 0), 2),
            "post_count":       sub_threat_counts.get(sub, 0),
        }

    return combined


# ══════════════════════════════════════════════════════════════════════════════
# MongoDB storage
# ══════════════════════════════════════════════════════════════════════════════

def _store_report(report: dict):
    """Save the full report dict to the 'reports' collection in MongoDB."""
    try:
        # Add project root to path if needed (for standalone execution)
        project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if project_root not in sys.path:
            sys.path.insert(0, project_root)
        from utils.mongo_client import get_collection
        collection = get_collection("reports")
        collection.update_one(
            {"report_id": report["report_id"]},
            {"$set": report},
            upsert=True,
        )
        log.info(f"Report saved to MongoDB — report_id={report['report_id']}")
    except ImportError:
        # Fallback: direct PyMongo connection if utils not available
        try:
            from pymongo import MongoClient
            client = MongoClient(MONGO_URI)
            db = client[MONGO_DB]
            db["reports"].update_one(
                {"report_id": report["report_id"]},
                {"$set": report},
                upsert=True,
            )
            client.close()
            log.info(f"Report saved to MongoDB (direct) — report_id={report['report_id']}")
        except Exception as e:
            log.error(f"Failed to save report to MongoDB: {e}")
    except Exception as e:
        log.error(f"Failed to save report to MongoDB: {e}")


# ══════════════════════════════════════════════════════════════════════════════
# CLI Printer
# ══════════════════════════════════════════════════════════════════════════════

def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def _print_report(report: dict):
    """Pretty-print the full report to terminal."""
    W = 100

    print("\n" + "═" * W)
    print(f"  📋  InsightGraph — Threat Intelligence Report")
    print(f"  Report ID : {report['report_id']}")
    print(f"  Generated : {report['generated_at']}")
    print("═" * W)

    # ── Executive Summary ──
    print(f"\n{BOLD}  📝 EXECUTIVE SUMMARY{RESET}")
    print("─" * W)
    summary_text = report.get("executive_summary", "No summary available.")
    # Word-wrap at ~90 chars
    words = summary_text.split()
    line = "  "
    for word in words:
        if len(line) + len(word) + 1 > 95:
            print(line)
            line = "  " + word
        else:
            line += " " + word if line.strip() else "  " + word
    if line.strip():
        print(line)

    # ── Threat Breakdown ──
    print(f"\n{BOLD}  🛡️  THREAT BREAKDOWN{RESET}")
    print("─" * W)
    threat_summary = report.get("threat_summary", {})
    by_sev = threat_summary.get("by_severity", {})
    by_type = threat_summary.get("by_type", {})

    print(f"\n  Total Analyzed: {threat_summary.get('total_analyzed', 0)}  |  "
          f"Threats Found: {threat_summary.get('total_threats', 0)}")

    print(f"\n  {'Severity':<12} {'Count':>6}")
    print(f"  {'─'*12} {'─'*6}")
    for sev in ["CRITICAL", "HIGH", "MEDIUM"]:
        count = by_sev.get(sev, 0)
        bar = "█" * min(count, 40)
        print(f"  {_color(sev, f'{sev:<12}')} {count:>6}  {bar}")

    if by_type:
        print(f"\n  {'Threat Type':<20} {'Count':>6}")
        print(f"  {'─'*20} {'─'*6}")
        for ttype, count in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
            print(f"  {ttype:<20} {count:>6}")

    # ── Combined Risk by Subreddit ──
    combined_risk = report.get("combined_risk_by_subreddit", {})
    if combined_risk:
        print(f"\n{BOLD}  ⚠️  COMBINED RISK BY SUBREDDIT{RESET}")
        print("─" * W)
        print(f"\n  {'Subreddit':<25} {'Risk Score':>10} {'Label':<10} {'Threat Avg':>10} {'Prop. Score':>11} {'Posts':>6}")
        print(f"  {'─'*25} {'─'*10} {'─'*10} {'─'*10} {'─'*11} {'─'*6}")
        for sub, data in sorted(combined_risk.items(), key=lambda x: x[1]["risk_score"], reverse=True):
            label_colored = _color(data["risk_label"], f"{data['risk_label']:<10}")
            print(
                f"  {sub[:23]:<25} {data['risk_score']:>10.1f} {label_colored} "
                f"{data['avg_threat_score']:>10.1f} {data['propagation_score']:>11.1f} {data['post_count']:>6}"
            )

    # ── Propagation Overview ──
    print(f"\n{BOLD}  🔗 PROPAGATION OVERVIEW{RESET}")
    print("─" * W)
    prop = report.get("propagation_summary", {})
    role_dist = prop.get("role_distribution", {})

    print(f"\n  Total Users: {prop.get('total_users', 0)}  |  "
          f"Total Edges: {prop.get('total_edges', 0)}")

    if role_dist:
        print(f"\n  {'Role':<15} {'Count':>6}")
        print(f"  {'─'*15} {'─'*6}")
        for role in ["Origin", "Amplifier", "Bridge", "Echo", "Endpoint"]:
            count = role_dist.get(role, 0)
            bar = "▓" * min(count, 40)
            print(f"  {role:<15} {count:>6}  {bar}")

    cascade = prop.get("cascade_depth", {})
    if cascade:
        print(f"\n  Cascade Depth — Max: {cascade.get('max', 0)}  |  "
              f"Avg: {cascade.get('average', 0):.1f}")

    velocity = prop.get("temporal_velocity", {})
    if velocity:
        print(f"  Temporal Velocity — Peak Hour: {velocity.get('peak_hour', '?')}  |  "
              f"Posts/Hour: {velocity.get('posts_per_hour', 0)}")

    # ── Key Actors ──
    key_actors = report.get("key_actors", [])
    if key_actors:
        print(f"\n{BOLD}  👤 KEY ACTORS{RESET}")
        print("─" * W)
        print(f"\n  {'Username':<25} {'Role':<12} {'Score':>8} {'Details'}")
        print(f"  {'─'*25} {'─'*12} {'─'*8} {'─'*40}")
        for actor in key_actors[:10]:
            print(
                f"  {actor.get('username', '?')[:23]:<25} "
                f"{actor.get('role', '?'):<12} "
                f"{actor.get('score', 0):>8.1f} "
                f"{actor.get('details', '')[:40]}"
            )

    # ── Top 5 Threats ──
    top_threats = report.get("top_threats", [])
    if top_threats:
        print(f"\n{BOLD}  🚨 TOP 5 THREATS{RESET}")
        print("─" * W)
        print(f"\n  {'#':<4} {'Post ID':<26} {'Subreddit':<20} {'Type':<16} {'Score':>6} {'Severity'}")
        print(f"  {'─'*4} {'─'*26} {'─'*20} {'─'*16} {'─'*6} {'─'*10}")
        for i, t in enumerate(top_threats[:5], 1):
            sev_colored = _color(t.get("severity", "CLEAN"), f"{t.get('severity', 'CLEAN'):<10}")
            print(
                f"  {i:<4} {t.get('post_id', '?')[:24]:<26} "
                f"{str(t.get('subreddit', '?'))[:18]:<20} "
                f"{t.get('threat_type', '?'):<16} "
                f"{t.get('threat_score', 0):>6.1f} {sev_colored}"
            )
            if t.get("text_preview"):
                print(f"       ↳ 📝 {t['text_preview'][:80]}")

    # ── IOC List ──
    iocs = report.get("ioc_list", [])
    if iocs:
        print(f"\n{BOLD}  🔍 IOC LIST ({len(iocs)} domains){RESET}")
        print("─" * W)
        for ioc in iocs[:20]:
            print(f"  • {ioc}")

    # ── Recommendations ──
    recs = report.get("recommendations", [])
    if recs:
        print(f"\n{BOLD}  💡 RECOMMENDATIONS{RESET}")
        print("─" * W)
        for i, rec in enumerate(recs, 1):
            print(f"\n  {i}. {rec}")

    # ── Footer ──
    print("\n" + "═" * W)
    print(f"  ✅ Report generation complete — report_id: {report['report_id']}")
    print("═" * W + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# ReportAgent class
# ══════════════════════════════════════════════════════════════════════════════

class ReportAgent:
    """
    Final agent in the InsightGraph pipeline.
    Aggregates STIA + Community Agent results into a unified report.
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
            threat_results:      List of per-post threat dicts from STIA Agent.
            threat_summary:      Aggregated threat stats from STIA Agent.
            propagation_results: Propagation/community analysis from Community Agent.

        Returns:
            Full report dict (also saved to MongoDB and printed to CLI).
        """
        log.info("Report Agent started")

        # ── Step 1: Combined risk per subreddit ──
        log.info("Step 1 — Computing combined risk scores per subreddit")
        combined_risk = _compute_combined_risk(threat_results, propagation_results)
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
            report["executive_summary"] = _fallback_executive_summary(threat_summary, propagation_results)
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
            report["recommendations"] = _fallback_recommendations(threat_summary, propagation_results)
            log.info("  Recommendations generated via fallback (rule-based)")

        # ── Step 4: Save to MongoDB ──
        log.info("Step 4 — Saving report to MongoDB")
        _store_report(report)

        # ── Step 5: Print CLI report ──
        log.info("Step 5 — Printing report to CLI")
        _print_report(report)

        log.info("Report Agent complete")
        return report


# ══════════════════════════════════════════════════════════════════════════════
# Main — run standalone with mock data
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    # ── Mock STIA Agent results ──
    mock_threat_results = [
        {
            "post_id":      "abc123",
            "subreddit":    "r/Scams",
            "author":       "u/scammer01",
            "threat_type":  "Phishing",
            "confidence":   0.923,
            "threat_score": 87.5,
            "severity":     "CRITICAL",
            "flagged_urls": [
                {
                    "url":             "http://paypa1-secure.xyz/login",
                    "domain":          "paypa1-secure.xyz",
                    "domain_age_days": 12,
                    "typosquat":       True,
                    "suspicious":      True,
                }
            ],
            "iocs":         ["paypa1-secure.xyz"],
            "text_preview": "Your PayPal account has been suspended. Click here to verify...",
            "coordinated":  True,
            "analyzed_at":  "2026-09-19T10:00:00Z",
        },
        {
            "post_id":      "def456",
            "subreddit":    "r/CryptoCurrency",
            "author":       "u/crypto_promo",
            "threat_type":  "Baiting",
            "confidence":   0.812,
            "threat_score": 62.3,
            "severity":     "HIGH",
            "flagged_urls": [],
            "iocs":         [],
            "text_preview": "Free BTC giveaway! Send 0.1 ETH to receive 1 BTC back...",
            "coordinated":  False,
            "analyzed_at":  "2026-09-19T10:01:00Z",
        },
        {
            "post_id":      "ghi789",
            "subreddit":    "r/Scams",
            "author":       "u/phisher42",
            "threat_type":  "Malware",
            "confidence":   0.956,
            "threat_score": 91.2,
            "severity":     "CRITICAL",
            "flagged_urls": [
                {
                    "url":             "http://amaz0n-gift.com/download",
                    "domain":          "amaz0n-gift.com",
                    "domain_age_days": 5,
                    "typosquat":       True,
                    "suspicious":      True,
                }
            ],
            "iocs":         ["amaz0n-gift.com"],
            "text_preview": "Download the Amazon gift card generator here...",
            "coordinated":  True,
            "analyzed_at":  "2026-09-19T10:02:00Z",
        },
        {
            "post_id":      "jkl012",
            "subreddit":    "r/phishing",
            "author":       "u/legit_user",
            "threat_type":  "NOT-Malicious",
            "confidence":   0.887,
            "threat_score": 0.0,
            "severity":     "CLEAN",
            "flagged_urls": [],
            "iocs":         [],
            "text_preview": "How do I report a phishing email I received today?",
            "coordinated":  False,
            "analyzed_at":  "2026-09-19T10:03:00Z",
        },
        {
            "post_id":      "mno345",
            "subreddit":    "r/Scams",
            "author":       "u/warning_poster",
            "threat_type":  "Pretexting",
            "confidence":   0.745,
            "threat_score": 48.2,
            "severity":     "MEDIUM",
            "flagged_urls": [],
            "iocs":         [],
            "text_preview": "Got a call from someone claiming to be IRS agent...",
            "coordinated":  False,
            "analyzed_at":  "2026-09-19T10:04:00Z",
        },
    ]

    mock_threat_summary = {
        "total_analyzed":    100,
        "total_threats":     23,
        "by_severity":       {"CRITICAL": 3, "HIGH": 8, "MEDIUM": 12},
        "by_type":           {"Phishing": 10, "Malware": 3, "Scareware": 4, "Baiting": 4, "Pretexting": 2},
        "top_iocs":          ["paypa1-secure.xyz", "amaz0n-gift.com"],
        "coordinated_count": 5,
    }

    # ── Mock Community Agent results ──
    mock_propagation_results = {
        "total_users":     87,
        "total_edges":     143,
        "role_distribution": {
            "Amplifier": 5,
            "Bridge":    3,
            "Origin":    12,
            "Echo":      34,
            "Endpoint":  33,
        },
        "top_amplifiers": [
            {"username": "u/scammer01",   "propagation_score": 82.4, "out_degree": 14, "subreddits": ["r/Scams", "r/CryptoCurrency"]},
            {"username": "u/crypto_promo", "propagation_score": 74.1, "out_degree": 9,  "subreddits": ["r/phishing"]},
        ],
        "top_bridges": [
            {"username": "u/bridge_user", "betweenness": 0.42, "connects": ["r/Scams", "r/personalfinance"]},
        ],
        "cascade_depth":              {"max": 5, "average": 2.3},
        "temporal_velocity":          {"peak_hour": "14:00", "posts_per_hour": 12},
        "most_affected_subreddits":   ["r/Scams", "r/CryptoCurrency", "r/phishing"],
    }

    # ── Run Report Agent ──
    agent = ReportAgent()
    report = agent.run(
        threat_results=mock_threat_results,
        threat_summary=mock_threat_summary,
        propagation_results=mock_propagation_results,
    )
