"""
main.py — InsightGraph entry point

Runs the full LangGraph pipeline:
    Threat Analyzer → Community Agent → Report Agent
"""

from pipeline import run_pipeline

if __name__ == "__main__":
    SUBREDDIT = "buildapc"  # ← change to your target subreddit

    result = run_pipeline(subreddit=SUBREDDIT)