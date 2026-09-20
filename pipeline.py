"""
pipeline.py — LangGraph orchestration for InsightGraph

Connects the three agents into a stateful graph:
    threat_analyzer_agent → community_agent → report_agent → END

Usage:
    from pipeline import run_pipeline
    result = run_pipeline(subreddit="buildapc")
"""

import logging
from typing import TypedDict, Any
from collections import Counter

from langgraph.graph import StateGraph, END

from agents.threat_analyzer import fetch_posts, analyze_post, print_results as print_threat_results
from agents.community_agent import CommunityAgent
from agents.report import ReportAgent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [PIPELINE] %(levelname)s — %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("pipeline")


# ══════════════════════════════════════════════════════════════════════════════
# Shared state schema
# ══════════════════════════════════════════════════════════════════════════════

class PipelineState(TypedDict, total=False):
    """State that flows through the LangGraph pipeline."""
    # Input
    subreddit: str

    # After threat_analyzer node
    posts: list[dict]
    post_ids: list[str]
    threat_results: list[dict]
    threat_summary: dict

    # After community node
    propagation_results: dict

    # After report node
    report: dict


# ══════════════════════════════════════════════════════════════════════════════
# Node functions
# ══════════════════════════════════════════════════════════════════════════════

def threat_analyzer_node(state: PipelineState) -> dict:
    """
    Node 1: Fetch posts from MongoDB, run threat analysis on each post,
    aggregate summary statistics, and print results.
    """
    subreddit = state["subreddit"]
    log.info(f"=== Threat Analyzer Agent — r/{subreddit} ===")

    # Fetch posts
    posts = fetch_posts(subreddit=subreddit)
    post_ids = [p["id"] for p in posts]

    if not posts:
        log.warning("No posts found — skipping analysis")
        return {
            "posts": [],
            "post_ids": [],
            "threat_results": [],
            "threat_summary": _empty_threat_summary(),
        }

    # Analyze each post
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

    # Print threat results
    print_threat_results(results)

    # Build summary
    threats = [r for r in results if r["severity"] != "CLEAN"]
    sev_counts = Counter(r["severity"] for r in threats)
    type_counts = Counter(r["threat_type"] for r in threats)
    all_iocs = list(set(ioc for r in threats for ioc in r.get("iocs", []) if ioc))

    threat_summary = {
        "total_analyzed":    len(results),
        "total_threats":     len(threats),
        "by_severity":       dict(sev_counts),
        "by_type":           dict(type_counts),
        "top_iocs":          sorted(all_iocs)[:10],
        "coordinated_count": sum(1 for r in threats if r.get("coordinated")),
    }

    return {
        "posts": posts,
        "post_ids": post_ids,
        "threat_results": results,
        "threat_summary": threat_summary,
    }


def community_node(state: PipelineState) -> dict:
    """
    Node 2: Build interaction graph, compute propagation metrics,
    detect communities, and store results.
    Only processes posts that were flagged as threats by the Threat Analyzer.
    """
    log.info("=== Community Agent ===")

    # Filter to only threat-detected post IDs (severity != CLEAN)
    threat_results = state.get("threat_results", [])
    threat_post_ids = [
        r["post_id"] for r in threat_results
        if r.get("severity", "CLEAN") != "CLEAN"
    ]

    log.info(
        f"Filtering: {len(threat_post_ids)} threat posts "
        f"out of {len(state.get('post_ids', []))} total"
    )

    if not threat_post_ids:
        log.warning("No threat posts detected — skipping community analysis")
        return {"propagation_results": _empty_propagation()}

    agent = CommunityAgent()
    raw_result = agent.run(post_ids=threat_post_ids)

    if not raw_result:
        return {"propagation_results": _empty_propagation()}

    # Transform raw community result into the format expected by ReportAgent
    metrics = raw_result.get("metrics", {})
    roles = raw_result.get("roles", {})
    cascade_depths = raw_result.get("cascade_depths", {})
    temporal_velocity = raw_result.get("temporal_velocity", {})

    # Build role distribution
    role_counts = Counter(roles.values())

    # Find top amplifiers
    amplifiers = [
        {
            "username": u,
            "propagation_score": m.get("propagation_score", 0),
            "out_degree": m.get("out_degree", 0),
            "subreddits": [],  # not directly available from metrics
        }
        for u, m in metrics.items()
        if roles.get(u) == "Amplifier"
    ]
    amplifiers.sort(key=lambda x: x["propagation_score"], reverse=True)

    # Find top bridges
    bridges = [
        {
            "username": u,
            "betweenness": m.get("betweenness_centrality", 0),
            "connects": [],
        }
        for u, m in metrics.items()
        if roles.get(u) == "Bridge"
    ]
    bridges.sort(key=lambda x: x["betweenness"], reverse=True)

    # Cascade depth summary
    cascade_summary = {}
    if cascade_depths:
        cascade_summary = {
            "max": max(cascade_depths.values()) if cascade_depths else 0,
            "average": sum(cascade_depths.values()) / len(cascade_depths) if cascade_depths else 0,
        }

    # Temporal velocity summary
    velocity_summary = {}
    if temporal_velocity:
        peak_hour = max(temporal_velocity, key=temporal_velocity.get)
        velocity_summary = {
            "peak_hour": str(peak_hour),
            "posts_per_hour": temporal_velocity[peak_hour],
        }

    propagation_results = {
        "total_users":              len(metrics),
        "total_edges":              sum(m.get("out_degree", 0) for m in metrics.values()),
        "role_distribution":        dict(role_counts),
        "top_amplifiers":           amplifiers[:5],
        "top_bridges":              bridges[:5],
        "cascade_depth":            cascade_summary,
        "temporal_velocity":        velocity_summary,
        "most_affected_subreddits": [],
    }

    return {"propagation_results": propagation_results}


def report_node(state: PipelineState) -> dict:
    """
    Node 3: Generate the final consolidated report using all upstream data.
    """
    log.info("=== Report Agent ===")

    threat_results = state.get("threat_results", [])
    threat_summary = state.get("threat_summary", _empty_threat_summary())
    propagation_results = state.get("propagation_results", _empty_propagation())

    agent = ReportAgent()
    report = agent.run(
        threat_results=threat_results,
        threat_summary=threat_summary,
        propagation_results=propagation_results,
    )

    return {"report": report}


# ══════════════════════════════════════════════════════════════════════════════
# Helper defaults
# ══════════════════════════════════════════════════════════════════════════════

def _empty_threat_summary() -> dict:
    return {
        "total_analyzed": 0, "total_threats": 0,
        "by_severity": {}, "by_type": {},
        "top_iocs": [], "coordinated_count": 0,
    }


def _empty_propagation() -> dict:
    return {
        "total_users": 0, "total_edges": 0,
        "role_distribution": {},
        "top_amplifiers": [], "top_bridges": [],
        "cascade_depth": {}, "temporal_velocity": {},
        "most_affected_subreddits": [],
    }


# ══════════════════════════════════════════════════════════════════════════════
# Build LangGraph pipeline
# ══════════════════════════════════════════════════════════════════════════════

def build_pipeline() -> StateGraph:
    """
    Construct the LangGraph StateGraph connecting:
        threat_analyzer → community → report → END
    """
    graph = StateGraph(PipelineState)

    # Add nodes
    graph.add_node("threat_analyzer", threat_analyzer_node)
    graph.add_node("community", community_node)
    graph.add_node("report", report_node)

    # Define edges (sequential pipeline)
    graph.set_entry_point("threat_analyzer")
    graph.add_edge("threat_analyzer", "community")
    graph.add_edge("community", "report")
    graph.add_edge("report", END)

    return graph.compile()


def run_pipeline(subreddit: str) -> dict:
    """
    Build and run the full InsightGraph pipeline for the given subreddit.

    Args:
        subreddit: The target subreddit name (without r/ prefix).

    Returns:
        Final pipeline state dict containing all results.
    """
    log.info(f"Starting InsightGraph pipeline for r/{subreddit}")
    pipeline = build_pipeline()
    result = pipeline.invoke({"subreddit": subreddit})
    log.info("Pipeline complete")
    return result
