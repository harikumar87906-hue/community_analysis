"""
STIA MongoDB Fetcher — fetches posts from a specific subreddit.
"""

from pymongo import MongoClient
from .config import log, MONGO_URI, MONGO_DB, POSTS_COL


def fetch_posts(subreddit: str) -> list[dict]:
    """
    Connect to MongoDB and fetch ALL posts from the given subreddit.
    Returns list of dicts with keys: id, text, subreddit, url.
    """
    log.info(f"Connecting to MongoDB: {MONGO_URI} → db={MONGO_DB}")
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)

    # Test connection
    client.admin.command("ping")
    log.info("MongoDB connection OK")

    db   = client[MONGO_DB]
    col  = db[POSTS_COL]

    query_filter = {"subreddit": subreddit}
    total = col.count_documents(query_filter)
    log.info(f"Collection '{POSTS_COL}' has {total} posts in r/{subreddit}")

    raw_docs = list(col.find(query_filter))

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
