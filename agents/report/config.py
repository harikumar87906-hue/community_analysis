"""
Report Agent configuration — logging, MongoDB, Ollama, and terminal constants.
"""

import os
import sys
import logging
import warnings
from dotenv import load_dotenv

load_dotenv()
warnings.filterwarnings("ignore")

# Fix Windows terminal encoding for Unicode output
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")
if sys.stderr.encoding != "utf-8":
    sys.stderr.reconfigure(encoding="utf-8")

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
