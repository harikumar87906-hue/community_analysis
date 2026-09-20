"""
agents.stia — Social Threat Intelligence Agent (modularized)

Public API:
    fetch_posts(subreddit)  — fetch all posts from a subreddit
    analyze_post(post)      — analyze a single post for threats
    print_results(results)  — pretty-print analysis results
"""

from .mongo_fetcher import fetch_posts
from .analyzer import analyze_post
from .printer import print_results
from .model_loader import ModelBundle

__all__ = ["fetch_posts", "analyze_post", "print_results", "ModelBundle"]
