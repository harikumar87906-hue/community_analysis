"""
Threat Analyzer URL Checker — URL extraction, expansion, and reputation checks.
"""

import re
import base64
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests
import whois

from .config import (
    VT_API_KEY, GSB_API_KEY,
    DOMAIN_AGE_THRESHOLD_DAYS,
    BRAND_NAMES, CRED_PATH_KEYWORDS,
)


def extract_urls(text: str) -> list[str]:
    """Extract all HTTP/HTTPS URLs from text."""
    return re.findall(r"https?://[^\s\"'>]+", text)


def expand_url(url: str, timeout: int = 4) -> str:
    """Follow redirects to get the final destination URL."""
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        return r.url
    except Exception:
        return url


def get_domain(url: str) -> str:
    """Extract the domain from a URL."""
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def check_virustotal(url: str) -> int:
    """Check URL against VirusTotal. Returns number of malicious/suspicious flags."""
    if not VT_API_KEY:
        return 0
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=8,
        )
        if resp.status_code == 200:
            stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
            return stats.get("malicious", 0) + stats.get("suspicious", 0)
    except Exception:
        pass
    return 0


def check_gsb(urls: list[str]) -> set[str]:
    """Check URLs against Google Safe Browsing. Returns set of flagged URLs."""
    if not GSB_API_KEY or not urls:
        return set()
    try:
        payload = {
            "client": {"clientId": "insightgraph", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": u} for u in urls],
            },
        }
        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_API_KEY}",
            json=payload, timeout=8,
        )
        if resp.status_code == 200:
            return {m["threat"]["url"] for m in resp.json().get("matches", [])}
    except Exception:
        pass
    return set()


def domain_age_days(domain: str):
    """Return the age of the domain in days, or None if unknown."""
    try:
        w = whois.whois(domain)
        created = w.creation_date
        if isinstance(created, list):
            created = created[0]
        if created:
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            return (datetime.now(timezone.utc) - created).days
    except Exception:
        pass
    return None


def is_typosquat(domain: str) -> bool:
    """Check if domain looks like a typosquat of a known brand."""
    normalized = domain.replace("4","a").replace("0","o").replace("3","e").replace("1","i")
    for brand in BRAND_NAMES:
        if brand in normalized and not normalized.endswith(f"{brand}.com"):
            return True
    return False


def has_cred_path(url: str) -> bool:
    """Check if URL path contains credential-harvesting keywords."""
    path = urlparse(url).path.lower()
    return any(kw in path for kw in CRED_PATH_KEYWORDS)
