"""
stia_agent.py — Social Threat Intelligence Agent
Replaces: misinfo_agent.py

Detects 6 threat types in Reddit posts using:
  - all-MiniLM-L6-v2 embeddings (CPU-friendly, no VRAM)
  - SVM classifier trained on Zenodo xlsx dataset
  - URL reputation checks (VirusTotal / Google Safe Browsing)
  - Domain age check via WHOIS
  - Coordination detection via MongoDB

Dataset labels: Phishing, Malware, Scareware, Baiting, Pretexting, NOT-Malicious

Run directly:
    python agents/stia_agent.py
"""

import os
import re
import json
import base64
import logging
import warnings
from collections import Counter
from datetime import datetime, timezone
from urllib.parse import urlparse

import joblib
import requests
import whois
import numpy as np
from pymongo import MongoClient
from dotenv import load_dotenv
from sentence_transformers import SentenceTransformer

load_dotenv()
warnings.filterwarnings("ignore")

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [STIA] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("stia_agent")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR   = os.path.join(BASE_DIR, "models")
CONFIG_PATH = os.path.join(MODEL_DIR, "stia_config.json")
CLF_PATH    = os.path.join(MODEL_DIR, "stia_classifier.pkl")
LE_PATH     = os.path.join(MODEL_DIR, "stia_label_encoder.pkl")

# ── MongoDB config (from .env) ────────────────────────────────────────────────
MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB    = os.getenv("MONGO_DB", "insightgraph")
POSTS_COL   = os.getenv("POSTS_COLLECTION", "posts")      # collection name
SAMPLE_SIZE = 100                                          # random posts to fetch

# ── API Keys (optional — from .env) ──────────────────────────────────────────
VT_API_KEY  = os.getenv("VIRUSTOTAL_API_KEY", "")
GSB_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_KEY", "")

# ── Thresholds ────────────────────────────────────────────────────────────────
DOMAIN_AGE_THRESHOLD_DAYS = 30
COORDINATION_WINDOW_SECS  = 3600
COORDINATION_MIN_COUNT    = 3
CONFIDENCE_THRESHOLD      = 0.45

# ── Label config — matches xlsx dataset ──────────────────────────────────────
SEVERITY_MAP = {
    "Phishing":      "HIGH",
    "Malware":       "CRITICAL",
    "Scareware":     "MEDIUM",
    "Baiting":       "MEDIUM",
    "Pretexting":    "HIGH",
    "NOT-Malicious": "CLEAN",
}

THREAT_WEIGHTS = {
    "Phishing":      0.25,
    "Malware":       0.35,
    "Scareware":     0.15,
    "Baiting":       0.10,
    "Pretexting":    0.15,
    "NOT-Malicious": 0.0,
}

SEVERITY_THRESHOLDS = {
    "CRITICAL": 80,
    "HIGH":     55,
    "MEDIUM":   30,
    "CLEAN":     0,
}

# Severity colors for terminal output
SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "CLEAN":    "\033[92m",   # green
}
RESET = "\033[0m"

# ── Suspicious URL path keywords ──────────────────────────────────────────────
CRED_PATH_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "account",
    "secure", "update", "confirm", "auth", "credential",
    "password", "recover", "unlock", "validate",
]

# ── Known brands for typosquat check ─────────────────────────────────────────
BRAND_NAMES = [
    "amazon", "google", "apple", "microsoft", "facebook",
    "paypal", "netflix", "instagram", "twitter", "coinbase",
    "hdfc", "sbi", "icici", "tesla", "youtube",
]


# ══════════════════════════════════════════════════════════════════════════════
# Model Loader — singleton, loads once
# ══════════════════════════════════════════════════════════════════════════════

class _ModelBundle:
    _instance = None

    def __init__(self):
        self.embedder = None
        self.clf      = None
        self.le       = None
        self.config   = None
        self._loaded  = False

    @classmethod
    def get(cls):
        if cls._instance is None:
            cls._instance = cls()
        if not cls._instance._loaded:
            cls._instance._load()
        return cls._instance

    def _load(self):
        log.info("Loading STIA models ...")
        if not os.path.exists(CLF_PATH):
            raise FileNotFoundError(
                f"Classifier not found at {CLF_PATH}.\n"
                "  → Run notebooks/stia_training.ipynb first to train and save the model."
            )
        with open(CONFIG_PATH) as f:
            self.config = json.load(f)
        self.embedder = SentenceTransformer(self.config["embedder_name"])
        self.clf      = joblib.load(CLF_PATH)
        self.le       = joblib.load(LE_PATH)
        self._loaded  = True
        log.info(
            f"Models ready | embedder={self.config['embedder_name']} "
            f"| classes={self.config['label_names']}"
        )


# ══════════════════════════════════════════════════════════════════════════════
# MongoDB — fetch random posts
# ══════════════════════════════════════════════════════════════════════════════

def fetch_random_posts(n: int = SAMPLE_SIZE) -> list[dict]:
    """
    Connect to MongoDB and fetch n random posts from the posts collection.
    Handles both 'posts' and 'comments' collections.
    Returns list of dicts with keys: id, text, subreddit, url.
    """
    log.info(f"Connecting to MongoDB: {MONGO_URI} → db={MONGO_DB}")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

    # Test connection
    client.admin.command("ping")
    log.info("MongoDB connection OK")

    db   = client[MONGO_DB]
    col  = db[POSTS_COL]
    total = col.count_documents({})
    log.info(f"Collection '{POSTS_COL}' has {total} documents — sampling {n}")

    # $sample gives truly random documents
    pipeline = [{"$sample": {"size": n}}]
    raw_docs = list(col.aggregate(pipeline))

    posts = []
    for doc in raw_docs:
        # Flexible field mapping — handles different schemas
        text = (
            doc.get("selftext")      # Reddit post body
            or doc.get("body")       # Reddit comment body
            or doc.get("title")      # fallback to title
            or doc.get("text")       # generic
            or ""
        ).strip()

        if not text or text in ("[deleted]", "[removed]"):
            continue

        posts.append({
            "id":        str(doc.get("_id", doc.get("id", "unknown"))),
            "text":      text,
            "subreddit": doc.get("subreddit", doc.get("subreddit_name_prefixed", "unknown")),
            "url":       doc.get("url", ""),
            "author":    doc.get("author", "unknown"),
            "score":     doc.get("score", 0),
            "created":   doc.get("created_utc", ""),
        })

    client.close()
    log.info(f"Fetched {len(posts)} valid posts after filtering blanks/deleted")
    return posts


# ══════════════════════════════════════════════════════════════════════════════
# URL helpers
# ══════════════════════════════════════════════════════════════════════════════

def _extract_urls(text: str) -> list[str]:
    return re.findall(r"https?://[^\s\"'>]+", text)

def _expand_url(url: str, timeout: int = 4) -> str:
    try:
        r = requests.head(url, allow_redirects=True, timeout=timeout)
        return r.url
    except Exception:
        return url

def _get_domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""

def _check_virustotal(url: str) -> int:
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

def _check_gsb(urls: list[str]) -> set[str]:
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

def _domain_age_days(domain: str):
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

def _is_typosquat(domain: str) -> bool:
    normalized = domain.replace("4","a").replace("0","o").replace("3","e").replace("1","i")
    for brand in BRAND_NAMES:
        if brand in normalized and not normalized.endswith(f"{brand}.com"):
            return True
    return False

def _has_cred_path(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(kw in path for kw in CRED_PATH_KEYWORDS)


# ══════════════════════════════════════════════════════════════════════════════
# Core analyzer
# ══════════════════════════════════════════════════════════════════════════════

def analyze_post(post: dict) -> dict:
    """
    Analyze a single post dict and return a threat result dict.
    """
    bundle = _ModelBundle.get()
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
    raw_urls    = _extract_urls(text)
    if post.get("url"):
        raw_urls.append(post["url"])
    expanded    = [_expand_url(u) for u in raw_urls]
    unique_urls = list(set(expanded))

    gsb_flagged = _check_gsb(unique_urls)
    url_details = []
    for url in unique_urls:
        domain   = _get_domain(url)
        vt_score = _check_virustotal(url)
        age      = _domain_age_days(domain)
        tsquat   = _is_typosquat(domain)
        credpath = _has_cred_path(url)
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


# ══════════════════════════════════════════════════════════════════════════════
# Print helpers
# ══════════════════════════════════════════════════════════════════════════════

def _color(severity: str, text: str) -> str:
    return f"{SEVERITY_COLORS.get(severity, '')}{text}{RESET}"

def print_results(results: list[dict]):
    """Pretty-print all 100 results to terminal."""
    threats = [r for r in results if r["severity"] != "CLEAN"]
    clean   = [r for r in results if r["severity"] == "CLEAN"]

    W = 100
    print("\n" + "═" * W)
    print(f"  🛡️  STIA — Social Threat Intelligence Agent — MongoDB Analysis")
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
    print("  📊 SUMMARY")
    print("─" * W)

    sev_counts  = Counter(r["severity"]  for r in results)
    type_counts = Counter(r["threat_type"] for r in threats)
    all_iocs    = [ioc for r in threats for ioc in r["iocs"]]

    print(f"\n  Severity Breakdown:")
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "CLEAN"]:
        count = sev_counts.get(sev, 0)
        bar   = "█" * count
        print(f"    {_color(sev, f'{sev:<10}')} {count:>3}  {bar}")

    if type_counts:
        print(f"\n  Threat Types Detected:")
        for ttype, count in type_counts.most_common():
            print(f"    {ttype:<20} {count} post(s)")

    if all_iocs:
        print(f"\n  Top IoCs (suspicious domains):")
        for ioc, count in Counter(all_iocs).most_common(10):
            print(f"    {ioc:<40} seen {count}×")

    sub_counts = Counter(r["subreddit"] for r in threats)
    if sub_counts:
        print(f"\n  Most Affected Subreddits:")
        for sub, count in sub_counts.most_common(5):
            print(f"    {str(sub):<30} {count} threat(s)")

    print("\n" + "═" * W)
    print(f"  ✅ Analysis complete — {len(threats)} threat(s) found in {len(results)} posts")
    print("═" * W + "\n")


# ══════════════════════════════════════════════════════════════════════════════
# Main — run directly
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Step 1 — Fetch 100 random posts from MongoDB
    try:
        posts = fetch_random_posts(n=SAMPLE_SIZE)
    except Exception as e:
        log.error(f"MongoDB fetch failed: {e}")
        log.info("Tip: Check MONGO_URI and MONGO_DB in your .env file")
        raise SystemExit(1)

    if not posts:
        log.error("No valid posts returned from MongoDB. Check collection name.")
        raise SystemExit(1)

    # Step 2 — Load models
    try:
        _ModelBundle.get()
    except FileNotFoundError as e:
        log.error(str(e))
        raise SystemExit(1)

    # Step 3 — Analyze all posts
    log.info(f"Analyzing {len(posts)} posts ...")
    results = []
    for i, post in enumerate(posts, 1):
        try:
            result = analyze_post(post)
            results.append(result)
            if i % 20 == 0:
                log.info(f"  Progress: {i}/{len(posts)}")
        except Exception as e:
            log.warning(f"Skipped post {post.get('id')}: {e}")

    # Step 4 — Print results
    print_results(results)