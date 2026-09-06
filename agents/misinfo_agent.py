# ============================================================
# InsightGraph — Misinformation Agent
# agents/misinfo_agent.py
# ============================================================

import os
import numpy as np
import pandas as pd
import faiss
import torch
from typing import TypedDict, List, Optional
from dotenv import load_dotenv
from transformers import (
    AutoTokenizer,
    AutoModel,
    pipeline as hf_pipeline
)
from langgraph.graph import StateGraph, END
from utils.mongo_client import get_collection

load_dotenv()

# ── Paths ────────────────────────────────────────────────────
BERT_MODEL_PATH = os.getenv("BERT_MODEL_PATH", "./bert-misinfo-finetuned")
FAISS_INDEX_PATH = os.getenv("FAISS_INDEX_PATH", "./faiss_kb/factcheck.index")
FAISS_DOCS_PATH  = os.getenv("FAISS_DOCS_PATH",  "./faiss_kb/factcheck_docs.pkl")

# ── Device ───────────────────────────────────────────────────
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"[MisinfoAgent] Using device : {device}")

# ── Load BERT Classifier ─────────────────────────────────────
print("[MisinfoAgent] Loading BERT classifier...")
bert_classifier = hf_pipeline(
    "text-classification",
    model=BERT_MODEL_PATH,
    tokenizer=BERT_MODEL_PATH,
    device=0 if torch.cuda.is_available() else -1
)

# ── Load BERT Encoder for embeddings ─────────────────────────
print("[MisinfoAgent] Loading BERT encoder...")
tokenizer  = AutoTokenizer.from_pretrained(BERT_MODEL_PATH)
bert_model = AutoModel.from_pretrained(BERT_MODEL_PATH).to(device)
bert_model.eval()

# ── Load FAISS Index ─────────────────────────────────────────
print("[MisinfoAgent] Loading FAISS index...")
faiss_index = faiss.read_index(FAISS_INDEX_PATH)
kb_df       = pd.read_pickle(FAISS_DOCS_PATH)
print(f"[MisinfoAgent] FAISS loaded — {faiss_index.ntotal} vectors")

# ── MongoDB ──────────────────────────────────────────────────
posts_col   = get_collection("posts")
results_col = get_collection("misinfo_results")

FALSE_VERDICTS = ["false", "pants-fire", "barely-true"]


# ============================================================
# State
# ============================================================

class MisinfoState(TypedDict):
    post_id         : str
    text            : str
    author          : str
    cluster_id      : int
    timestamp       : str
    bert_label      : Optional[str]
    bert_confidence : Optional[float]
    rag_evidence    : Optional[List[dict]]
    propagation     : Optional[dict]
    final_score     : Optional[float]
    high_risk       : Optional[bool]


# ============================================================
# Helpers
# ============================================================

def get_embedding(texts: list) -> np.ndarray:
    inputs = tokenizer(
        texts,
        return_tensors="pt",
        truncation=True,
        padding=True,
        max_length=128
    ).to(device)

    with torch.no_grad():
        outputs = bert_model(**inputs)

    embeddings = outputs.last_hidden_state[:, 0, :].cpu().numpy()
    norms = np.linalg.norm(embeddings, axis=1, keepdims=True)
    return (embeddings / norms).astype(np.float32)


# ============================================================
# Node 1 — BERT Classification
# ============================================================

def bert_classify_node(state: MisinfoState) -> MisinfoState:
    result = bert_classifier(
        state["text"],
        truncation=True,
        max_length=128
    )[0]
    state["bert_label"]      = result["label"]
    state["bert_confidence"] = round(result["score"], 3)
    print(f"  [BERT] {state['bert_label']} ({state['bert_confidence']})")
    return state


# ============================================================
# Node 2 — RAG Retrieval
# ============================================================

def rag_retrieve_node(state: MisinfoState) -> MisinfoState:
    query_emb = get_embedding([state["text"]])
    scores, indices = faiss_index.search(query_emb, k=3)

    evidence = []
    for score, idx in zip(scores[0], indices[0]):
        if score > 0.60:
            row = kb_df.iloc[idx]
            evidence.append({
                "claim"      : row["statement"],
                "verdict"    : row["label"],
                "speaker"    : row["speaker"],
                "similarity" : round(float(score), 3)
            })

    state["rag_evidence"] = evidence
    print(f"  [RAG] {len(evidence)} evidence retrieved")
    return state


# ============================================================
# Node 3 — Propagation Analysis
# ============================================================

def propagation_node(state: MisinfoState) -> MisinfoState:
    from datetime import datetime

    # Find similar posts in MongoDB using embedding similarity
    query_emb = get_embedding([state["text"]])

    # Pull all posts from same or other clusters
    all_posts = list(posts_col.find(
        {"post_id": {"$ne": state["post_id"]}},
        {"post_id": 1, "text": 1, "author": 1,
         "cluster_id": 1, "timestamp": 1}
    ).limit(500))  # limit for performance

    similar_posts = []
    for post in all_posts:
        try:
            post_emb = get_embedding([post["text"]])
            score = float(np.dot(query_emb[0], post_emb[0]))
            if score > 0.75:
                similar_posts.append({
                    "cluster_id" : post.get("cluster_id"),
                    "author"     : post.get("author"),
                    "timestamp"  : post.get("timestamp"),
                    "similarity" : round(score, 3)
                })
        except Exception:
            continue

    # Clusters affected
    clusters = list({p["cluster_id"] for p in similar_posts
                     if p["cluster_id"] is not None})

    # Spread velocity
    timestamps = []
    for p in similar_posts:
        try:
            timestamps.append(datetime.fromisoformat(str(p["timestamp"])))
        except Exception:
            continue

    if len(timestamps) >= 2:
        timestamps.sort()
        velocity_hrs = (
            timestamps[-1] - timestamps[0]
        ).total_seconds() / 3600
    else:
        velocity_hrs = 0.0

    # Amplifier users (posted across multiple clusters)
    amplifiers = list({
        p["author"] for p in similar_posts
        if p.get("cluster_id") != state["cluster_id"]
    })[:5]

    state["propagation"] = {
        "clusters_affected"  : clusters,
        "cross_community"    : len(clusters) > 1,
        "spread_velocity_hrs": round(velocity_hrs, 2),
        "amplifier_users"    : amplifiers,
        "similar_posts_found": len(similar_posts)
    }
    print(f"  [PROP] clusters={clusters} | cross={len(clusters) > 1}")
    return state


# ============================================================
# Node 4 — Aggregator + Save
# ============================================================

def aggregator_node(state: MisinfoState) -> MisinfoState:
    # BERT score
    bert_score = state.get("bert_confidence", 0)
    if state.get("bert_label") != "FAKE":
        bert_score = 1 - bert_score

    # Evidence score
    evidence_score = 0.0
    for e in state.get("rag_evidence", []):
        if e["verdict"] in FALSE_VERDICTS:
            evidence_score = max(evidence_score, e["similarity"])

    # Propagation score
    prop_score = 0.3 if state.get(
        "propagation", {}).get("cross_community") else 0.0

    # Weighted final score
    final = round(
        (0.50 * bert_score) +
        (0.35 * evidence_score) +
        (0.15 * prop_score), 3
    )

    state["final_score"] = final
    state["high_risk"]   = final > 0.7

    # Save to MongoDB
    results_col.update_one(
        {"post_id": state["post_id"]},
        {"$set": state},
        upsert=True
    )
    print(f"  [AGG] final_score={final} | high_risk={state['high_risk']}")
    return state


# ============================================================
# Build LangGraph
# ============================================================

def build_misinfo_agent():
    g = StateGraph(MisinfoState)

    g.add_node("bert_classify", bert_classify_node)
    g.add_node("rag_retrieve",  rag_retrieve_node)
    g.add_node("propagation",   propagation_node)
    g.add_node("aggregate",     aggregator_node)

    g.set_entry_point("bert_classify")
    g.add_edge("bert_classify", "rag_retrieve")
    g.add_edge("rag_retrieve",  "propagation")
    g.add_edge("propagation",   "aggregate")
    g.add_edge("aggregate",     END)

    return g.compile()


# misinfo_agent = build_misinfo_agent()
# print("[MisinfoAgent] Graph compiled ✅")

class MisinfoAgent:
    def __init__(self, batch_size: int = 4):
        self.batch_size = batch_size
        self.posts_col  = get_collection("posts")
        self.graph      = build_misinfo_agent()
        print(f"[MisinfoAgent] Initialized | batch_size={batch_size}")

    def _fetch_posts(self):
        analyzed_ids = {
            doc["post_id"]
            for doc in get_collection("misinfo_results").find(
                {}, {"post_id": 1}
            )
        }

        all_posts = list(self.posts_col.find(
            {},
            {"post_id": 1, "text": 1, "author": 1,
             "cluster_id": 1, "timestamp": 1}
        ))

        pending = [
            p for p in all_posts
            if str(p.get("post_id", "")) not in analyzed_ids
        ]

        print(f"[MisinfoAgent] Total   : {len(all_posts)}")
        print(f"[MisinfoAgent] Done    : {len(analyzed_ids)}")
        print(f"[MisinfoAgent] Pending : {len(pending)}")
        return pending

    def _build_state(self, post: dict) -> dict:
        return {
            "post_id"         : str(post.get("post_id", "")),
            "text"            : post.get("text", ""),
            "author"          : post.get("author", ""),
            "cluster_id"      : post.get("cluster_id", 0),
            "timestamp"       : str(post.get("timestamp", "")),
            "bert_label"      : None,
            "bert_confidence" : None,
            "rag_evidence"    : None,
            "propagation"     : None,
            "final_score"     : None,
            "high_risk"       : None
        }

    def run(self):
        posts = self._fetch_posts()

        if not posts:
            print("[MisinfoAgent] No pending posts — exiting")
            return {"status": "done", "processed": 0}

        total     = len(posts)
        processed = 0
        high_risk = 0
        errors    = 0

        for i in range(0, total, self.batch_size):
            batch = posts[i:i + self.batch_size]
            print(f"\n[MisinfoAgent] Batch {i//self.batch_size + 1} "
                  f"| posts {i+1}–{min(i+self.batch_size, total)} of {total}")

            for post in batch:
                try:
                    state  = self._build_state(post)
                    result = self.graph.invoke(state)
                    processed += 1
                    if result.get("high_risk"):
                        high_risk += 1
                except Exception as e:
                    errors += 1
                    print(f"  [ERROR] {post.get('post_id')} → {e}")
                    continue

        summary = {
            "status"    : "done",
            "processed" : processed,
            "high_risk" : high_risk,
            "errors"    : errors
        }

        print(f"\n[MisinfoAgent] ✅ Complete")
        print(f"  Processed : {processed}")
        print(f"  High risk : {high_risk}")
        print(f"  Errors    : {errors}")

        return summary