"""
STIA configuration — constants, thresholds, paths, and logging.
"""

import os
import logging
import warnings
from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore")

# Suppress HuggingFace download / tokenizer logs
os.environ["HF_HUB_DISABLE_PROGRESS_BARS"] = "1"
os.environ["TOKENIZERS_PARALLELISM"] = "false"
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
logging.getLogger("transformers").setLevel(logging.WARNING)
logging.getLogger("huggingface_hub").setLevel(logging.WARNING)

# ── Logging ───────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [STIA] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("stia_agent")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MODEL_DIR   = os.path.join(BASE_DIR, "models")
CONFIG_PATH = os.path.join(MODEL_DIR, "stia_config.json")
CLF_PATH    = os.path.join(MODEL_DIR, "stia_classifier.pkl")
LE_PATH     = os.path.join(MODEL_DIR, "stia_label_encoder.pkl")

# ── MongoDB config (from .env) ────────────────────────────────────────────────
MONGO_URI   = os.getenv("MONGO_URI", "mongodb://localhost:27017")
MONGO_DB    = os.getenv("MONGO_DB", "insightgraph")
POSTS_COL   = os.getenv("POSTS_COLLECTION", "posts")

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
    "CRITICAL": 30,
    "HIGH":     20,
    "MEDIUM":   10,
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
