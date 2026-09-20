"""
report_agent.py — Backward-compatible re-export from agents.report package.

The actual implementation is now modularized under agents/report/:
    config.py   — logging, MongoDB, Ollama, terminal constants
    llm.py      — Ollama integration and fallback generators
    risk.py     — combined risk scoring per subreddit
    storage.py  — MongoDB persistence
    printer.py  — formatted CLI report output
    agent.py    — ReportAgent class
"""

from agents.report import ReportAgent

__all__ = ["ReportAgent"]


if __name__ == "__main__":

    # ── Mock Threat Analyzer Agent results ──
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
