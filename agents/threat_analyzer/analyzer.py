"""
Threat Analyzer — core threat analysis for a single post.
"""

from datetime import datetime, timezone

from .config import (
    CONFIDENCE_THRESHOLD,
    THREAT_WEIGHTS,
    SEVERITY_THRESHOLDS,
    DOMAIN_AGE_THRESHOLD_DAYS,
)
from .model_loader import ModelBundle
from .url_checker import (
    extract_urls, expand_url, get_domain,
    check_virustotal, check_gsb,
    domain_age_days, is_typosquat, has_cred_path,
)


def analyze_post(post: dict) -> dict:
    """
    Analyze a single post dict and return a threat result dict.
    """
    bundle = ModelBundle.get()
    text   = post.get("text", "") or ""

    # ── NLP classification ──
    emb         = bundle.embedder.encode([text], batch_size=1)
    pred_id     = bundle.clf.predict(emb)[0]
    probs       = bundle.clf.predict_proba(emb)[0]
    confidence  = float(probs.max())
    threat_type = bundle.le.inverse_transform([pred_id])[0]

    if confidence < CONFIDENCE_THRESHOLD:
        threat_type = "NOT-Malicious"

    # ── URL checks ──
    raw_urls    = extract_urls(text)
    if post.get("url"):
        raw_urls.append(post["url"])
    expanded    = [expand_url(u) for u in raw_urls]
    unique_urls = list(set(expanded))

    gsb_flagged = check_gsb(unique_urls)
    url_details = []
    for url in unique_urls:
        domain   = get_domain(url)
        vt_score = check_virustotal(url)
        age      = domain_age_days(domain)
        tsquat   = is_typosquat(domain)
        credpath = has_cred_path(url)
        flagged  = (
            url in gsb_flagged
            or vt_score > 0
            or (age is not None and age < DOMAIN_AGE_THRESHOLD_DAYS)
            or (tsquat and credpath)
        )
        url_details.append({
            "url": url, "domain": domain,
            "domain_age_days": age, "vt_score": vt_score,
            "gsb_flagged": url in gsb_flagged,
            "typosquat": tsquat, "cred_path": credpath,
            "suspicious": flagged,
        })

    flagged_urls = [u for u in url_details if u["suspicious"]]

    # ── Composite threat score ──
    base_score   = THREAT_WEIGHTS.get(threat_type, 0) * confidence * 100
    url_boost    = min(len(flagged_urls) * 15, 30)
    threat_score = min(round(base_score + url_boost, 2), 100)

    # ── Severity ──
    if threat_score >= SEVERITY_THRESHOLDS["CRITICAL"]:
        severity = "CRITICAL"
    elif threat_score >= SEVERITY_THRESHOLDS["HIGH"]:
        severity = "HIGH"
    elif threat_score >= SEVERITY_THRESHOLDS["MEDIUM"]:
        severity = "MEDIUM"
    else:
        severity = "CLEAN"

    if threat_type == "NOT-Malicious" and not flagged_urls:
        severity     = "CLEAN"
        threat_score = 0.0

    return {
        "post_id":      post.get("id", "?"),
        "subreddit":    post.get("subreddit", "?"),
        "author":       post.get("author", "?"),
        "score":        post.get("score", 0),
        "threat_type":  threat_type,
        "confidence":   round(confidence, 4),
        "threat_score": threat_score,
        "severity":     severity,
        "flagged_urls": flagged_urls,
        "iocs":         [u["domain"] for u in flagged_urls if u["domain"]],
        "text_preview": text[:120].replace("\n", " "),
        "analyzed_at":  datetime.now(timezone.utc).isoformat(),
    }
