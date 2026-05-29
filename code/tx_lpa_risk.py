# -*- coding: utf-8 -*-
import json
import random
import math


def parse_bool(value, default=True):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.lower() in ["true", "1", "yes", "y"]
    return bool(value)


def safe_get_field(vertex, field_names):
    for name in field_names:
        try:
            value = vertex.GetField(name)
            if value is not None:
                return str(value)
        except:
            continue
    return ""


def Process(db, input):
    data = json.loads(input)

    max_iter = int(data.get("max_iter", 20))
    top_k = int(data.get("top_k", 10))
    min_size = int(data.get("min_size", 10))
    sample_k = int(data.get("sample_k", 8))
    use_undirected = parse_bool(data.get("use_undirected", True), True)

    random.seed(42)

    txn = db.CreateReadTxn()

    # 1. collect vertices
    vids = []
    tx_info = {}

    it = txn.GetVertexIterator()
    while it.IsValid():
        vid = it.GetId()
        vids.append(vid)

        v = txn.GetVertexIterator(vid)
        txid = ""
        tx_class = ""

        if v.IsValid():
            txid = safe_get_field(v, ["txid", "txId", "TXID", "id"])
            tx_class = safe_get_field(v, ["tx_class", "class", "Class"])

        tx_info[vid] = {
            "txid": txid,
            "tx_class": tx_class
        }

        it.Next()

    if len(vids) == 0:
        txn.Abort()
        return (True, json.dumps({
            "message": "empty graph",
            "top_risk_communities": []
        }, ensure_ascii=False))

    # 2. build neighbor table
    neighbors = {vid: set() for vid in vids}
    original_edge_count = 0

    for vid in vids:
        v = txn.GetVertexIterator(vid)
        if not v.IsValid():
            continue

        edge_it = v.GetOutEdgeIterator()
        while edge_it.IsValid():
            dst = edge_it.GetDst()

            if dst in neighbors:
                neighbors[vid].add(dst)

                # For community detection, use weak-undirected relation by default.
                if use_undirected:
                    neighbors[dst].add(vid)

                original_edge_count += 1

            edge_it.Next()

    # 3. initialize labels
    labels = {vid: vid for vid in vids}

    # 4. label propagation
    actual_iter = 0
    last_changed = 0

    for i in range(max_iter):
        actual_iter = i + 1
        changed = 0

        order = vids[:]
        random.shuffle(order)

        for vid in order:
            nbrs = neighbors.get(vid, set())
            if not nbrs:
                continue

            label_freq = {}
            for nbr in nbrs:
                lbl = labels[nbr]
                label_freq[lbl] = label_freq.get(lbl, 0) + 1

            if not label_freq:
                continue

            max_count = max(label_freq.values())
            candidates = [lbl for lbl, cnt in label_freq.items() if cnt == max_count]
            new_label = random.choice(candidates)

            if new_label != labels[vid]:
                labels[vid] = new_label
                changed += 1

        last_changed = changed

        if changed == 0:
            break

    # 5. aggregate community statistics
    communities = {}

    for vid, cid in labels.items():
        if cid not in communities:
            communities[cid] = {
                "community_id": cid,
                "size": 0,
                "illicit_count": 0,
                "licit_count": 0,
                "unknown_count": 0,
                "sample_txids": []
            }

        communities[cid]["size"] += 1

        tx_class = tx_info[vid]["tx_class"]

        if tx_class == "1":
            communities[cid]["illicit_count"] += 1
        elif tx_class == "2":
            communities[cid]["licit_count"] += 1
        else:
            communities[cid]["unknown_count"] += 1

        if len(communities[cid]["sample_txids"]) < sample_k:
            communities[cid]["sample_txids"].append(tx_info[vid]["txid"])

    # 6. count internal and boundary edges
    for cid in communities:
        communities[cid]["internal_edges"] = 0
        communities[cid]["boundary_edges"] = 0

    for vid in vids:
        v = txn.GetVertexIterator(vid)
        if not v.IsValid():
            continue

        src_cid = labels[vid]

        edge_it = v.GetOutEdgeIterator()
        while edge_it.IsValid():
            dst = edge_it.GetDst()

            if dst in labels:
                dst_cid = labels[dst]

                if src_cid == dst_cid:
                    communities[src_cid]["internal_edges"] += 1
                else:
                    communities[src_cid]["boundary_edges"] += 1

            edge_it.Next()

    # 7. calculate risk score
    result_communities = []

    for cid, info in communities.items():
        size = info["size"]

        if size < min_size:
            continue

        illicit = info["illicit_count"]
        licit = info["licit_count"]
        unknown = info["unknown_count"]
        internal_edges = info["internal_edges"]
        boundary_edges = info["boundary_edges"]

        known_total = illicit + licit
        illicit_ratio_known = illicit / known_total if known_total > 0 else 0.0
        unknown_ratio = unknown / size if size > 0 else 0.0

        edge_total = internal_edges + boundary_edges
        cohesion = internal_edges / edge_total if edge_total > 0 else 0.0

        risk_score = illicit_ratio_known * math.log(1 + size) * (1 + unknown_ratio) * (1 + cohesion)

        result_communities.append({
            "community_id": cid,
            "size": size,
            "illicit_count": illicit,
            "licit_count": licit,
            "unknown_count": unknown,
            "illicit_ratio_known": round(illicit_ratio_known, 6),
            "unknown_ratio": round(unknown_ratio, 6),
            "internal_edges": internal_edges,
            "boundary_edges": boundary_edges,
            "cohesion": round(cohesion, 6),
            "risk_score": round(risk_score, 6),
            "sample_txids": info["sample_txids"]
        })

    result_communities = sorted(
        result_communities,
        key=lambda x: (x["risk_score"], x["illicit_count"], x["size"]),
        reverse=True
    )

    txn.Abort()

    result = {
        "algorithm": "Label Propagation Algorithm",
        "task": "Bitcoin transaction risk community detection",
        "parameters": {
            "max_iter": max_iter,
            "actual_iter": actual_iter,
            "last_changed": last_changed,
            "top_k": top_k,
            "min_size": min_size,
            "sample_k": sample_k,
            "use_undirected": use_undirected
        },
        "graph_summary": {
            "num_vertices": len(vids),
            "num_edges": original_edge_count
        },
        "community_summary": {
            "num_communities_total": len(communities),
            "num_communities_after_filter": len(result_communities)
        },
        "risk_score_definition": "risk_score = illicit_ratio_known * log(1 + size) * (1 + unknown_ratio) * (1 + cohesion)",
        "top_risk_communities": result_communities[:top_k]
    }

    return (True, json.dumps(result, ensure_ascii=False))
