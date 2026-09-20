"""
Report Agent Printer — formatted CLI report output.
"""

from .config import SEVERITY_COLORS, RESET, BOLD


def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_report(report: dict):
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
        print(f"  {_color(sev, f'{sev:<12}')} {count:>6}")

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
            print(f"  {role:<15} {count:>6}")

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
