from datetime import datetime, timezone

from graph.graph_builder import build_graph
from graph.community_detector import (
    get_centrality,
    compute_propagation_metrics,
    assign_propagation_roles,
    compute_cascade_depth,
    compute_temporal_velocity,
)
from utils.mongo_client import get_collection
from utils.neo4j_client import get_driver


def store_to_neo4j(graph_data, metrics, roles):
    driver = get_driver()
    with driver.session() as session:
        # Clear existing data
        session.run("MATCH (n) DETACH DELETE n")

        # 1. Create Subreddit nodes
        if graph_data["subreddits"]:
            session.run(
                """
                UNWIND $subreddits AS sub
                MERGE (s:Subreddit {name: sub})
                """,
                subreddits=graph_data["subreddits"]
            )

        # 2. Create User nodes with propagation attributes
        users_payload = []
        for u in graph_data["users"]:
            m = metrics.get(u, {})
            users_payload.append({
                "name": str(u),
                "role": roles.get(u, "Endpoint"),
                "propagation_score": float(m.get("propagation_score", 0.0)),
                "pagerank": float(m.get("pagerank", 0.0)),
                "betweenness": float(m.get("betweenness_centrality", 0.0)),
                "in_degree": int(m.get("in_degree", 0)),
                "out_degree": int(m.get("out_degree", 0)),
            })

        if users_payload:
            session.run(
                """
                UNWIND $users AS u
                MERGE (user:User {name: u.name})
                SET user.role = u.role,
                    user.propagation_score = u.propagation_score,
                    user.pagerank = u.pagerank,
                    user.betweenness = u.betweenness,
                    user.in_degree = u.in_degree,
                    user.out_degree = u.out_degree
                """,
                users=users_payload
            )

        # 3. Create Post nodes
        if graph_data["posts"]:
            session.run(
                """
                UNWIND $posts AS p
                MERGE (post:Post {post_id: p.post_id})
                SET post.title = p.title,
                    post.content = p.content,
                    post.author = p.author,
                    post.score = p.score,
                    post.num_comments = p.num_comments,
                    post.timestamp = p.timestamp,
                    post.subreddit = p.subreddit
                """,
                posts=graph_data["posts"]
            )

        # 4. Create Comment nodes
        if graph_data["comments"]:
            session.run(
                """
                UNWIND $comments AS c
                MERGE (comment:Comment {comment_id: c.comment_id})
                SET comment.post_id = c.post_id,
                    comment.parent_id = c.parent_id,
                    comment.author = c.author,
                    comment.content = c.content,
                    comment.score = c.score,
                    comment.timestamp = c.timestamp,
                    comment.subreddit = c.subreddit
                """,
                comments=graph_data["comments"]
            )

        # 5. Create (User)-[:CREATED]->(Post)
        if graph_data["user_created_posts"]:
            payload = [{"author": a, "post_id": pid} for a, pid in graph_data["user_created_posts"]]
            session.run(
                """
                UNWIND $edges AS e
                MATCH (u:User {name: e.author})
                MATCH (p:Post {post_id: e.post_id})
                MERGE (u)-[:CREATED]->(p)
                """,
                edges=payload
            )

        # 6. Create (Subreddit)-[:CONTAINS]->(Post)
        if graph_data["subreddit_contains_posts"]:
            payload = [{"subreddit": s, "post_id": pid} for s, pid in graph_data["subreddit_contains_posts"]]
            session.run(
                """
                UNWIND $edges AS e
                MATCH (s:Subreddit {name: e.subreddit})
                MATCH (p:Post {post_id: e.post_id})
                MERGE (s)-[:CONTAINS]->(p)
                """,
                edges=payload
            )

        # 7. Create (Post)-[:HAS_COMMENT]->(Comment)
        if graph_data["post_has_comments"]:
            payload = [{"post_id": pid, "comment_id": cid} for pid, cid in graph_data["post_has_comments"]]
            session.run(
                """
                UNWIND $edges AS e
                MATCH (p:Post {post_id: e.post_id})
                MATCH (c:Comment {comment_id: e.comment_id})
                MERGE (p)-[:HAS_COMMENT]->(c)
                """,
                edges=payload
            )

        # 8. Create (Comment)-[:CREATED_BY]->(User)
        if graph_data["comment_created_by_user"]:
            payload = [{"comment_id": cid, "author": a} for cid, a in graph_data["comment_created_by_user"]]
            session.run(
                """
                UNWIND $edges AS e
                MATCH (c:Comment {comment_id: e.comment_id})
                MATCH (u:User {name: e.author})
                MERGE (c)-[:CREATED_BY]->(u)
                """,
                edges=payload
            )

        # 9. Create (User)-[:REPLIED_TO]->(User)
        if graph_data["user_replied_to_user"]:
            session.run(
                """
                UNWIND $edges AS e
                MATCH (u1:User {name: e.from_user})
                MATCH (u2:User {name: e.to_user})
                MERGE (u1)-[r:REPLIED_TO]->(u2)
                SET r.weight = e.weight
                """,
                edges=graph_data["user_replied_to_user"]
            )

    print(f"  Complete heterogeneous graph stored in Neo4j.")


def store_propagation_to_mongo(metrics, roles):
    """
    Stores propagation analysis results into the 'propagation' MongoDB collection.
    """
    collection = get_collection("propagation")
    collection.drop()

    documents = []
    analyzed_at = datetime.now(timezone.utc)

    for username, m in metrics.items():
        documents.append({
            "username": username,
            "role": roles.get(username, "Endpoint"),
            "pagerank": round(float(m.get("pagerank", 0.0)), 6),
            "betweenness": round(float(m.get("betweenness_centrality", 0.0)), 6),
            "in_degree": int(m.get("in_degree", 0)),
            "out_degree": int(m.get("out_degree", 0)),
            "propagation_score": round(float(m.get("propagation_score", 0.0)), 6),
            "analyzed_at": analyzed_at,
        })

    if documents:
        collection.insert_many(documents)
        print(f"  {len(documents)} propagation records stored in MongoDB")


def print_results(metrics, roles, cascade_depths, temporal_velocity):
    """
    Prints a clean CLI table of propagation results and summary.
    """
    # Sort users by propagation_score descending
    sorted_users = sorted(
        metrics.items(),
        key=lambda x: x[1].get("propagation_score", 0),
        reverse=True
    )

    # Print table header
    print("\n" + "=" * 90)
    print(f"{'Username':<25} {'Role':<12} {'Prop.Score':>10} {'In-Deg':>8} {'Out-Deg':>8} {'PageRank':>10}")
    print("-" * 90)

    for username, m in sorted_users[:30]:  # Top 30 users
        role = roles.get(username, "Endpoint")
        print(
            f"{username:<25} {role:<12} "
            f"{m.get('propagation_score', 0):>10.6f} "
            f"{m.get('in_degree', 0):>8} "
            f"{m.get('out_degree', 0):>8} "
            f"{m.get('pagerank', 0):>10.6f}"
        )

    print("=" * 90)

    # Role counts summary
    from collections import Counter
    role_counts = Counter(roles.values())
    print(f"\n--- Role Distribution ---")
    for role_name in ["Origin", "Amplifier", "Bridge", "Echo", "Endpoint"]:
        count = role_counts.get(role_name, 0)
        print(f"  {role_name:<12}: {count}")
    print(f"  {'Total':<12}: {len(roles)}")

    # Cascade depth summary
    if cascade_depths:
        max_depth = max(cascade_depths.values()) if cascade_depths else 0
        avg_depth = sum(cascade_depths.values()) / len(cascade_depths) if cascade_depths else 0
        print(f"\n--- Cascade Depth ---")
        print(f"  Components  : {len(cascade_depths)}")
        print(f"  Max depth   : {max_depth}")
        print(f"  Avg depth   : {avg_depth:.2f}")

    # Temporal velocity summary
    if temporal_velocity:
        total_posts = sum(temporal_velocity.values())
        active_hours = len(temporal_velocity)
        peak_hour = max(temporal_velocity, key=temporal_velocity.get)
        peak_count = temporal_velocity[peak_hour]
        print(f"\n--- Temporal Velocity ---")
        print(f"  Total posts : {total_posts}")
        print(f"  Active hours: {active_hours}")
        print(f"  Peak hour   : {peak_hour} ({peak_count} posts)")


class CommunityAgent:
    def run(self, post_ids=None, posts=None):

        print("\nBuilding multi-entity and interaction graphs.")
        graph_data, G_user = build_graph(posts=posts, post_ids=post_ids)

        if len(graph_data["users"]) == 0 and len(graph_data["posts"]) == 0:
            print("  Graph is empty — no data found in MongoDB.")
            return {}

        print("\nComputing propagation metrics.")
        metrics = compute_propagation_metrics(G_user)

        print("\nAssigning propagation roles.")
        roles = assign_propagation_roles(G_user, metrics)

        print("\nComputing network centrality metrics (Degree, PageRank, Betweenness).")
        centrality_dict = get_centrality(G_user)

        print("\nComputing cascade depths.")
        cascade_depths = compute_cascade_depth(G_user)

        print("\nComputing temporal velocity.")
        temporal_velocity = compute_temporal_velocity(graph_data["posts"])

        print("\nStoring complete graph into Neo4j.")
        store_to_neo4j(graph_data, metrics, roles)

        print("\nStoring propagation analysis into MongoDB.")
        store_propagation_to_mongo(metrics, roles)

        print_results(metrics, roles, cascade_depths, temporal_velocity)

        return {
            "metrics": metrics,
            "roles": roles,
            "centrality": centrality_dict,
            "cascade_depths": cascade_depths,
            "temporal_velocity": temporal_velocity,
        }