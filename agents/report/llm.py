"""
Report Agent LLM — Ollama integration and fallback generators.
"""

import json
import requests

from .config import log, OLLAMA_URL, OLLAMA_MODEL


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

def fallback_executive_summary(threat_summary: dict, propagation_results: dict) -> str:
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


def fallback_recommendations(threat_summary: dict, propagation_results: dict) -> list[str]:
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
