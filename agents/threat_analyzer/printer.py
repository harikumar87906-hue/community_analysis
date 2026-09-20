"""
Threat Analyzer Printer — pretty-print threat analysis results to terminal.
"""

from collections import Counter
from .config import SEVERITY_COLORS, RESET


def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"


def print_results(results: list[dict]):
    """Pretty-print all results to terminal."""
    threats = [r for r in results if r["severity"] != "CLEAN"]
    clean   = [r for r in results if r["severity"] == "CLEAN"]

    W = 100
    print("\n" + "═" * W)
    print(f"  Threat Analyzer — Social Threat Intelligence Analysis")
    print(f"  Total analyzed: {len(results)}  |  Threats: {len(threats)}  |  Clean: {len(clean)}")
    print("═" * W)

    # ── Per-result table ──
    print(f"\n{'#':<4} {'Post ID':<26} {'Subreddit':<22} {'Threat Type':<16} {'Conf':>5} {'Score':>6}  {'Severity'}")
    print("-" * W)

    for i, r in enumerate(results, 1):
        sev_label = _color(r["severity"], f"{r['severity']:<8}")
        print(
            f"{i:<4}"
            f"{r['post_id'][:24]:<26}"
            f"{str(r['subreddit'])[:20]:<22}"
            f"{r['threat_type']:<16}"
            f"{r['confidence']:>5.3f}"
            f"{r['threat_score']:>7.1f}  "
            f"{sev_label}"
        )
        # Show text preview for threats
        if r["severity"] != "CLEAN":
            print(f"     ↳ 📝 {r['text_preview'][:90]}")
        # Show flagged URLs
        for u in r["flagged_urls"]:
            age_str = f"age={u['domain_age_days']}d" if u["domain_age_days"] is not None else "age=?"
            print(f"     ↳ 🔗 {u['url'][:70]}  {age_str}  typosquat={u['typosquat']}")

    # ── Summary ──
    print("\n" + "═" * W)
    print("  SUMMARY")
    print("─" * W)

    sev_counts  = Counter(r["severity"]  for r in results)
    type_counts = Counter(r["threat_type"] for r in threats)
    all_iocs    = [ioc for r in threats for ioc in r["iocs"]]

    print(f"\n  Severity Breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "CLEAN"]:
        count = sev_counts.get(sev, 0)
        print(f"    {_color(sev, f'{sev:<10}')} {count:>3}")

    if type_counts:
        print(f"\n  Threat Types Detected:")
        for ttype, count in type_counts.most_common():
            print(f"    {ttype:<20} {count} post(s)")

    if all_iocs:
        print(f"\n  Top IoCs (suspicious domains):")
        for ioc, count in Counter(all_iocs).most_common(10):
            print(f"    {ioc:<40} seen {count}×")

    print("\n" + "═" * W)
    print(f"  Analysis complete — {len(threats)} threat(s) found in {len(results)} posts")
    print("═" * W + "\n")
