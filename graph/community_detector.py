import community as community_louvain
import networkx as nx


def _compute_pagerank(G, alpha=0.85, max_iter=100, tol=1.0e-6, weight="weight"):
    """
    Computes PageRank with pure Python power iteration fallback if scipy is unavailable.
    """
    if len(G) == 0:
        return {}

    try:
        return nx.pagerank(G, alpha=alpha, max_iter=max_iter, tol=tol, weight=weight)
    except Exception:
        pass

    # Pure Python power iteration implementation
    nodes = list(G.nodes())
    N = len(nodes)
    if N == 0:
        return {}

    x = {n: 1.0 / N for n in nodes}
    out_weights = {}
    for n in nodes:
        total = sum(d.get(weight, 1) for _, _, d in G.edges(n, data=True))
        out_weights[n] = total

    for _ in range(max_iter):
        xlast = x.copy()
        x = {n: 0.0 for n in nodes}
        danglesum = alpha * sum(xlast[n] for n in nodes if out_weights[n] == 0)

        for n in nodes:
            if out_weights[n] > 0:
                for _, nbr, d in G.edges(n, data=True):
                    w = d.get(weight, 1)
                    x[nbr] += alpha * xlast[n] * (w / out_weights[n])

        dangling_share = danglesum / N
        teleport_share = (1.0 - alpha) / N
        for n in nodes:
            x[n] += dangling_share + teleport_share

        err = sum(abs(x[n] - xlast[n]) for n in nodes)
        if err < tol:
            break

    s = sum(x.values()) or 1.0
    return {n: float(v / s) for n, v in x.items()}


def detect_communities(G):
    """
    Runs Louvain community detection on the user interaction graph.
    """
    if G.number_of_nodes() == 0:
        print("  Community detection skipped: graph has no nodes.")
        return {}, 0.0

    # Louvain requires an undirected graph
    G_undirected = G.to_undirected() if G.is_directed() else G

    if G_undirected.number_of_edges() == 0:
        # If no edges, assign each user to an individual community
        partition = {node: idx for idx, node in enumerate(G.nodes())}
        modularity = 0.0
    else:
        try:
            partition = community_louvain.best_partition(G_undirected, weight="weight")
            modularity = community_louvain.modularity(partition, G_undirected, weight="weight")
        except Exception as e:
            print(f"  Warning in Louvain detection: {e}, falling back to component-based partition")
            components = list(nx.connected_components(G_undirected))
            partition = {}
            for idx, comp in enumerate(components):
                for node in comp:
                    partition[node] = idx
            try:
                modularity = community_louvain.modularity(partition, G_undirected, weight="weight")
            except Exception:
                modularity = 0.0

    num_communities = len(set(partition.values()))
    print(f"  Communities detected: {num_communities}")
    print(f"  Modularity score   : {round(modularity, 4)}")
    return partition, modularity


def get_centrality(G):
    """
    Calculates Degree and PageRank centralities.
    """
    if G.number_of_nodes() == 0:
        return {"degree": {}, "pagerank": {}}

    degree   = nx.degree_centrality(G)
    pagerank = _compute_pagerank(G, weight="weight")

    return {
        "degree":   degree,
        "pagerank": pagerank
    }


def get_influential_users(partition, centrality_dict, top_n=5):
    """
    Ranks users within each community using centrality metrics.
    """
    pagerank = centrality_dict.get("pagerank", {})
    degree = centrality_dict.get("degree", {})

    community_ids = set(partition.values())
    influential = {}

    for comm_id in community_ids:
        members = [user for user, c in partition.items() if c == comm_id]

        ranked = sorted(
            members,
            key=lambda u: (pagerank.get(u, 0), degree.get(u, 0)),
            reverse=True
        )

        top_members = []
        for u in ranked[:top_n]:
            top_members.append({
                "username": u,
                "pagerank": round(pagerank.get(u, 0), 5),
                "degree": round(degree.get(u, 0), 5)
            })

        influential[comm_id] = top_members

    return influential