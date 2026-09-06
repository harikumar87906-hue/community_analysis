import random
import networkx as nx
from utils.mongo_client import get_collection


def build_graph(posts=None, comments=None):
    """
    Builds both:
    1. Complete multi-entity graph representation (Users, Posts, Comments, Subreddits, and relationships).
    2. User interaction graph (NetworkX Graph) for centrality and community detection.
    """
    if posts is None:
        posts_col = get_collection("posts")
        # posts = list(posts_col.find())

        # Only fetch posts that have at least 1 comment
        posts = list(posts_col.find({"num_comments": {"$gt": 0}}))

    if len(posts) > 1000:
        random.seed(42)
        posts = random.sample(posts, 1000)
    sampled_post_ids = [str(p.get("post_id", "")).strip() for p in posts]

    # Get only comments belonging to sampled posts
    if comments is None:
        comments_col = get_collection("comments")
        comments = list(comments_col.find({"post_id": {"$in": sampled_post_ids}}))

        

    # Helper to clean invalid authors
    def is_valid_author(author):
        return bool(author) and str(author).strip() not in ("", "[deleted]", "[removed]")

    users = set()
    subreddits = set()
    cleaned_posts = []
    cleaned_comments = []

    post_author_map = {}
    comment_author_map = {}
    comment_post_map = {}

    # 1. Process Posts (posts - sampled_post_ids)
    for p in posts:
        post_id = str(p.get("post_id", "")).strip()
        if not post_id:
            continue

        author = str(p.get("author", "")).strip()
        subreddit = str(p.get("subreddit", "")).strip()

        if is_valid_author(author):
            users.add(author)
            post_author_map[post_id] = author

        if subreddit:
            subreddits.add(subreddit)

        cleaned_posts.append({
            "post_id": post_id,
            "title": p.get("title", ""),
            "content": p.get("content", ""),
            "author": author,
            "score": int(p.get("score", 0)),
            "num_comments": int(p.get("num_comments", 0)),
            "timestamp": int(p.get("timestamp", 0)),
            "subreddit": subreddit
        })

    # 2. Process Comments
    for c in comments:
        comment_id = str(c.get("comment_id", "")).strip()
        if not comment_id:
            continue

        post_id = str(c.get("post_id", "")).strip()
        raw_parent = c.get("parent_id", "")
        parent_id = str(raw_parent).split("_", 1)[1] if (isinstance(raw_parent, str) and "_" in raw_parent) else str(raw_parent or "").strip()
        author = str(c.get("author", "")).strip()
        subreddit = str(c.get("subreddit", "")).strip()

        if is_valid_author(author):
            users.add(author)
            comment_author_map[comment_id] = author

        if post_id:
            comment_post_map[comment_id] = post_id

        if subreddit:
            subreddits.add(subreddit)

        cleaned_comments.append({
            "comment_id": comment_id,
            "post_id": post_id,
            "parent_id": parent_id,
            "author": author,
            "content": c.get("content", ""),
            "score": int(c.get("score", 0)),
            "timestamp": int(c.get("timestamp", 0)),
            "subreddit": subreddit
        })

    # 3. Build Relationships
    user_created_posts = []
    subreddit_contains_posts = []
    post_has_comments = []
    comment_created_by_user = []
    user_replies_count = {}  # (from_user, to_user) -> weight

    for p in cleaned_posts:
        if is_valid_author(p["author"]):
            user_created_posts.append((p["author"], p["post_id"]))
        if p["subreddit"]:
            subreddit_contains_posts.append((p["subreddit"], p["post_id"]))

    for c in cleaned_comments:
        c_id = c["comment_id"]
        p_id = c["post_id"]
        c_author = c["author"]
        parent_id = c["parent_id"]

        if p_id:
            post_has_comments.append((p_id, c_id))

        if is_valid_author(c_author):
            comment_created_by_user.append((c_id, c_author))

            # Determine who this comment replied to
            target_user = None
            if parent_id and parent_id in comment_author_map:
                target_user = comment_author_map[parent_id]
            elif p_id and p_id in post_author_map:
                target_user = post_author_map[p_id]

            if target_user and is_valid_author(target_user) and target_user != c_author:
                pair = (c_author, target_user)
                user_replies_count[pair] = user_replies_count.get(pair, 0) + 1

    # 4. Build User Interaction NetworkX Graph
    G_user = nx.Graph()
    for u in users:
        G_user.add_node(u, type="user")

    for (u1, u2), weight in user_replies_count.items():
        if G_user.has_edge(u1, u2):
            G_user[u1][u2]["weight"] += weight
        else:
            G_user.add_edge(u1, u2, weight=weight)

    user_replied_to_user = [
        {"from_user": u1, "to_user": u2, "weight": weight}
        for (u1, u2), weight in user_replies_count.items()
    ]

    graph_data = {
        "users": list(users),
        "subreddits": list(subreddits),
        "posts": cleaned_posts,
        "comments": cleaned_comments,
        "user_created_posts": user_created_posts,
        "subreddit_contains_posts": subreddit_contains_posts,
        "post_has_comments": post_has_comments,
        "comment_created_by_user": comment_created_by_user,
        "user_replied_to_user": user_replied_to_user,
    }

    print(f"\n--- Graph Construction Summary ---")
    print(f"  Users       : {len(users)}")
    print(f"  Subreddits  : {len(subreddits)}")
    print(f"  Posts       : {len(cleaned_posts)}")
    print(f"  Comments    : {len(cleaned_comments)}")
    print(f"  User Edges  : {G_user.number_of_edges()} interactions")

    return graph_data, G_user