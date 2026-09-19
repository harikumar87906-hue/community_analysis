from graph.graph_builder import build_graph
from graph.community_detector import detect_communities, get_centrality, get_influential_users
from utils.mongo_client import get_collection
from utils.neo4j_client import get_driver


def store_to_neo4j(graph_data, partition, centrality_dict):
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

        # 2. Create User nodes with community and centrality attributes
        users_payload = []
        deg = centrality_dict.get("degree", {})
        pr = centrality_dict.get("pagerank", {})

        for u in graph_data["users"]:
            users_payload.append({
                "name": str(u),
                "community": int(partition.get(u, -1)),
                "degree_centrality": float(deg.get(u, 0.0)),
                "pagerank": float(pr.get(u, 0.0))
            })

        if users_payload:
            session.run(
                """
                UNWIND $users AS u
                MERGE (user:User {name: u.name})
                SET user.community = u.community,
                    user.degree_centrality = u.degree_centrality,
                    user.pagerank = u.pagerank
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


def store_communities_to_mongo(partition, modularity, influential):
    collection = get_collection("communities")
    collection.drop()

    communities = []
    for comm_id in set(partition.values()):
        members = [user for user, c in partition.items() if c == comm_id]
        communities.append({
            "community_id":      int(comm_id),
            "members":           members,
            "size":              len(members),
            "influential_users": influential.get(comm_id, []),
            "modularity":        round(float(modularity), 4)
        })

    if communities:
        collection.insert_many(communities)
        print(f"  {len(communities)} communities stored in MongoDB")


class CommunityAgent:
    def run(self):

        print("\nBuilding multi-entity and interaction graphs.")
        graph_data, G_user = build_graph()

        if len(graph_data["users"]) == 0 and len(graph_data["posts"]) == 0:
            print("  Graph is empty — no data found in MongoDB.")
            return {}

        print("\nDetecting communities on user interactions.")
        partition, modularity = detect_communities(G_user)

        print("\nComputing network centrality metrics (Degree, PageRank).")
        centrality_dict = get_centrality(G_user)

        print("\nIdentifying influential users across communities.")
        influential = get_influential_users(partition, centrality_dict)

        print("\nStoring complete graph into Neo4j.")
        store_to_neo4j(graph_data, partition, centrality_dict)

        print("\nStoring community analysis into MongoDB.")
        store_communities_to_mongo(partition, modularity, influential)

        return {
            "num_communities": len(set(partition.values())),
            "modularity":      modularity,
            "partition":       partition,
            "influential":     influential,
            "centrality":      centrality_dict
        }