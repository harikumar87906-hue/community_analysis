import networkx as nx
from collections import defaultdict


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


def get_centrality(G):
    """
    Calculates Degree, PageRank, and Betweenness centralities.
    """
    if G.number_of_nodes() == 0:
        return {"degree": {}, "pagerank": {}, "betweenness": {}}

    degree   = nx.degree_centrality(G)
    pagerank = _compute_pagerank(G, weight="weight")
    betweenness = nx.betweenness_centrality(G, weight="weight")

    return {
        "degree":      degree,
        "pagerank":    pagerank,
        "betweenness": betweenness
    }


def compute_propagation_metrics(G):
    """
    Computes propagation metrics for each user in the directed graph.
    Returns a dict keyed by username with:
        pagerank, betweenness_centrality, in_degree, out_degree, propagation_score
    Composite: 0.4*pagerank + 0.4*betweenness + 0.2*out_degree_normalized
    """
    if G.number_of_nodes() == 0:
        return {}

    pagerank = _compute_pagerank(G, weight="weight")
    betweenness = nx.betweenness_centrality(G, weight="weight")

    # Compute raw in/out degrees
    in_degrees = dict(G.in_degree())
    out_degrees = dict(G.out_degree())

    # Normalize out_degree for composite score
    max_out = max(out_degrees.values()) if out_degrees else 1
    max_out = max(max_out, 1)  # avoid division by zero

    metrics = {}
    for node in G.nodes():
        pr = pagerank.get(node, 0.0)
        bc = betweenness.get(node, 0.0)
        in_deg = in_degrees.get(node, 0)
        out_deg = out_degrees.get(node, 0)
        out_deg_norm = out_deg / max_out

        propagation_score = 0.4 * pr + 0.4 * bc + 0.2 * out_deg_norm

        metrics[node] = {
            "pagerank": round(pr, 6),
            "betweenness_centrality": round(bc, 6),
            "in_degree": in_deg,
            "out_degree": out_deg,
            "propagation_score": round(propagation_score, 6)
        }

    return metrics


def assign_propagation_roles(G, metrics):
    """
    Labels each user with a propagation role based on their metrics:
        Origin    — high out_degree, low in_degree
        Amplifier — high out_degree AND high pagerank
        Bridge    — high betweenness
        Echo      — high in_degree, low out_degree
        Endpoint  — low everything
    Returns a dict {username: role}
    """
    if not metrics:
        return {}

    # Compute thresholds from metric distributions
    all_pr = [m["pagerank"] for m in metrics.values()]
    all_bc = [m["betweenness_centrality"] for m in metrics.values()]
    all_in = [m["in_degree"] for m in metrics.values()]
    all_out = [m["out_degree"] for m in metrics.values()]

    def percentile(values, pct):
        if not values:
            return 0
        s = sorted(values)
        idx = int(len(s) * pct / 100)
        idx = min(idx, len(s) - 1)
        return s[idx]

    pr_high = percentile(all_pr, 75)
    bc_high = percentile(all_bc, 75)
    in_high = percentile(all_in, 75)
    out_high = percentile(all_out, 75)
    in_low = percentile(all_in, 25)
    out_low = percentile(all_out, 25)

    roles = {}
    for node, m in metrics.items():
        pr = m["pagerank"]
        bc = m["betweenness_centrality"]
        in_deg = m["in_degree"]
        out_deg = m["out_degree"]

        if out_deg >= out_high and pr >= pr_high:
            roles[node] = "Amplifier"
        elif bc >= bc_high:
            roles[node] = "Bridge"
        elif out_deg >= out_high and in_deg <= in_low:
            roles[node] = "Origin"
        elif in_deg >= in_high and out_deg <= out_low:
            roles[node] = "Echo"
        else:
            roles[node] = "Endpoint"

    return roles


def compute_cascade_depth(G):
    """
    For each weakly connected component in the directed graph,
    find the longest path using nx.dag_longest_path_length().
    Returns dict of {component_root: depth}.
    Cycles are handled by falling back to diameter of the undirected version.
    """
    if G.number_of_nodes() == 0:
        return {}

    cascade_depths = {}
    for component_nodes in nx.weakly_connected_components(G):
        subgraph = G.subgraph(component_nodes)

        # Determine root (node with highest out_degree in component)
        root = max(component_nodes, key=lambda n: G.out_degree(n))

        try:
            depth = nx.dag_longest_path_length(subgraph)
        except nx.NetworkXUnfeasible:
            # Graph has cycles — fallback to undirected diameter approximation
            ug = subgraph.to_undirected()
            if ug.number_of_edges() > 0:
                try:
                    depth = nx.diameter(ug)
                except nx.NetworkXError:
                    depth = 0
            else:
                depth = 0

        cascade_depths[root] = depth

    return cascade_depths


def compute_temporal_velocity(posts):
    """
    Groups posts by hour using created_utc (timestamp) field.
    Returns a dict of {hour_bucket: count} representing posts per hour.
    """
    if not posts:
        return {}

    posts_per_hour = defaultdict(int)
    for p in posts:
        ts = p.get("timestamp", 0) or p.get("created_utc", 0) or p.get("created", 0)
        ts = int(ts)
        if ts > 0:
            hour_bucket = ts - (ts % 3600)  # Round down to nearest hour
            posts_per_hour[hour_bucket] += 1

    return dict(posts_per_hour)