"""
threat_analyzer_agent.py — Backward-compatible re-export from agents.threat_analyzer package.

The actual implementation is now modularized under agents/threat_analyzer/:
    config.py        — constants, thresholds, paths
    model_loader.py  — singleton embedder + classifier loader
    mongo_fetcher.py — MongoDB post fetcher
    url_checker.py   — URL extraction & reputation checks
    analyzer.py      — core threat analysis
    printer.py       — terminal output formatting
"""

from agents.threat_analyzer import fetch_posts, analyze_post, print_results, ModelBundle

__all__ = ["fetch_posts", "analyze_post", "print_results", "ModelBundle"]


if __name__ == "__main__":
    from agents.threat_analyzer.config import log

    # Step 1 — Fetch all posts from target subreddit
    try:
        posts = fetch_posts(subreddit="AskReddit")  # ← change subreddit here
    except Exception as e:
        log.error(f"MongoDB fetch failed: {e}")
        log.info("Tip: Check MONGO_URI and MONGO_DB in your .env file")
        raise SystemExit(1)

    if not posts:
        log.error("No valid posts returned from MongoDB. Check collection name.")
        raise SystemExit(1)

    # Step 2 — Load models
    try:
        ModelBundle.get()
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
