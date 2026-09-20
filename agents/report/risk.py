"""
Report Agent Risk Scoring — combined risk computation per subreddit.
"""


def compute_combined_risk(threat_results: list[dict], propagation_results: dict) -> dict:
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
