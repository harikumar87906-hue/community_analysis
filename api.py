"""
api.py — FastAPI backend for InsightGraph

Exposes the LangGraph pipeline as a REST API.

Run:
    uvicorn api:app --reload --port 8000
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from pipeline import run_pipeline


# ══════════════════════════════════════════════════════════════════════════════
# Request / Response schemas
# ══════════════════════════════════════════════════════════════════════════════

class AnalyzeRequest(BaseModel):
    subreddit: str


class AnalyzeResponse(BaseModel):
    status: str
    report: dict
    threat_summary: dict
    propagation_summary: dict
    threat_results: list[dict]


# ══════════════════════════════════════════════════════════════════════════════
# App
# ══════════════════════════════════════════════════════════════════════════════

app = FastAPI(
    title="InsightGraph API",
    description="Threat intelligence analysis pipeline for Reddit communities",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# Endpoints
# ══════════════════════════════════════════════════════════════════════════════

@app.get("/api/health")
def health():
    return {"status": "ok"}


@app.post("/api/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    """
    Run the full InsightGraph pipeline for the given subreddit.
    Returns the final report, threat summary, and propagation summary.
    """
    subreddit = req.subreddit.strip()
    if not subreddit:
        raise HTTPException(status_code=400, detail="subreddit is required")

    # Suppress noisy logs during API execution
    loggers_to_quiet = [
        "pipeline", "threat_analyzer", "report_agent",
        "stia_agent", "sentence_transformers", "transformers",
        "huggingface_hub", "urllib3", "httpx", "httpcore", "filelock",
    ]
    original_levels = {}
    for name in loggers_to_quiet:
        logger = logging.getLogger(name)
        original_levels[name] = logger.level
        logger.setLevel(logging.WARNING)

    try:
        result = run_pipeline(subreddit=subreddit)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        # Restore log levels
        for name, level in original_levels.items():
            logging.getLogger(name).setLevel(level)

    report = result.get("report", {})
    threat_summary = result.get("threat_summary", {})
    propagation_results = result.get("propagation_results", {})
    threat_results = result.get("threat_results", [])

    return AnalyzeResponse(
        status="success",
        report=report,
        threat_summary=threat_summary,
        propagation_summary=propagation_results,
        threat_results=threat_results,
    )
