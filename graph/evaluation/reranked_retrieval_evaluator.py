import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

from graph.retrieval.vector_retriever import VectorRetriever
from graph.retrieval.hybrid_retriever import HybridRetriever
from graph.retrieval.hybrid_reranker import ExperimentalHybridReranker


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

BENCHMARK_FILE = (
    PROJECT_ROOT
    / "data"
    / "evaluation"
    / "retrieval_benchmark.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "evaluation"
)

RESULT_FILE = (
    OUTPUT_DIR
    / "reranked_retrieval_results.json"
)

SUMMARY_FILE = (
    OUTPUT_DIR
    / "reranked_retrieval_summary.json"
)


# ============================================================
# CONFIGURATION
# ============================================================

TOP_K = 5


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv(PROJECT_ROOT / ".env")

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


# ============================================================
# LOAD BENCHMARK
# ============================================================

def load_benchmark():
    if not BENCHMARK_FILE.exists():
        raise FileNotFoundError(f"Benchmark file not found:\n{BENCHMARK_FILE}")

    with open(BENCHMARK_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


# ============================================================
# GRAPH BASELINE
# ============================================================

class GraphBaseline:
    def __init__(self, uri, username, password, database):
        self.driver = GraphDatabase.driver(uri, auth=(username, password))
        self.database = database
        self.driver.verify_connectivity()

    def search(self, query, top_k=5):
        words = [
            word.strip().lower()
            for word in query.split()
            if len(word.strip()) >= 4
        ]

        if not words:
            return []

        conditions = [
            f"""
            (
                toLower(coalesce(n.name, '')) CONTAINS $word{index}
                OR
                toLower(coalesce(n.description, '')) CONTAINS $word{index}
            )
            """
            for index in range(len(words))
        ]

        where_clause = " OR ".join(conditions)

        cypher = f"""
        MATCH (n:Technique)
        WHERE {where_clause}
        WITH n, reduce(score = 0, word IN $words |
            score + CASE
                WHEN toLower(coalesce(n.name, '')) CONTAINS word THEN 3
                WHEN toLower(coalesce(n.description, '')) CONTAINS word THEN 1
                ELSE 0
            END
        ) AS lexical_score
        RETURN n.name AS name, n.mitre_id AS mitre_id, n.description AS description, lexical_score
        ORDER BY lexical_score DESC, name ASC
        LIMIT $top_k
        """

        parameters = {"words": words, "top_k": top_k}
        for index, word in enumerate(words):
            parameters[f"word{index}"] = word

        with self.driver.session(database=self.database) as session:
            result = session.run(cypher, **parameters)
            records = list(result)

        formatted = []
        for rank, record in enumerate(records, start=1):
            formatted.append({
                "rank": rank,
                "name": record["name"],
                "mitre_id": record["mitre_id"],
                "lexical_score": record["lexical_score"]
            })

        return formatted

    def close(self):
        self.driver.close()


# ============================================================
# METRICS
# ============================================================

def precision_at_k(retrieved_ids, expected_ids, k=TOP_K):
    retrieved = retrieved_ids[:k]
    if not retrieved:
        return 0.0
    hits = sum(1 for item in retrieved if item in expected_ids)
    return hits / k


def recall_at_k(retrieved_ids, expected_ids, k=TOP_K):
    if not expected_ids:
        return 0.0
    retrieved = set(retrieved_ids[:k])
    hits = len(retrieved.intersection(expected_ids))
    return hits / len(expected_ids)


def reciprocal_rank(retrieved_ids, expected_ids):
    for rank, item in enumerate(retrieved_ids[:TOP_K], start=1):
        if item in expected_ids:
            return 1.0 / rank
    return 0.0


# ============================================================
# ID EXTRACTION HELPERS
# ============================================================

def extract_vector_ids(results, top_k=TOP_K):
    ids = []
    for result in results[:top_k]:
        metadata = result.get("metadata") or {}
        mitre_id = (
            result.get("mitre_id")
            or result.get("external_id")
            or metadata.get("mitre_id")
            or metadata.get("external_id")
        )
        if mitre_id and mitre_id not in ids:
            ids.append(mitre_id)
    return ids[:top_k]


def extract_hybrid_ids(context, top_k=TOP_K):
    fused_results = context.get("fused_results", [])
    ids = []
    for item in fused_results[:top_k]:
        mitre_id = item.get("mitre_id") or item.get("external_id")
        if mitre_id and mitre_id not in ids:
            ids.append(mitre_id)
    return ids[:top_k]


def extract_original_hybrid_ids(context, top_k=TOP_K):
    original_fused = context.get("original_fused_results")
    if original_fused is None:
        original_fused = context.get("fused_results", [])
    ids = []
    for item in original_fused[:top_k]:
        mitre_id = item.get("mitre_id") or item.get("external_id")
        if mitre_id and mitre_id not in ids:
            ids.append(mitre_id)
    return ids[:top_k]


# ============================================================
# EVALUATE ONE QUERY
# ============================================================

def evaluate_query(
    benchmark_item,
    vector_retriever,
    graph_retriever,
    orig_hybrid_retriever,
    reranked_hybrid_retriever
):
    query = benchmark_item["query"]
    expected_ids = set(benchmark_item["expected_mitre_ids"])
    query_id = benchmark_item["id"]

    print()
    print("=" * 70)
    print(f"QUERY {query_id}: {query}")
    print(f"EXPECTED MITRE IDs: {sorted(expected_ids)}")
    print("=" * 70)

    # 1. Vector Retrieval
    start = time.perf_counter()
    v_res = vector_retriever.search(query, top_k=TOP_K)
    v_latency = (time.perf_counter() - start) * 1000
    v_ids = extract_vector_ids(v_res, top_k=TOP_K)

    # 2. Graph Retrieval
    start = time.perf_counter()
    g_res = graph_retriever.search(query, top_k=TOP_K)
    g_latency = (time.perf_counter() - start) * 1000
    g_ids = [r["mitre_id"] for r in g_res[:TOP_K] if r.get("mitre_id")][:TOP_K]

    # 3. Original Hybrid GraphRAG
    start = time.perf_counter()
    h_orig_context = orig_hybrid_retriever.retrieve(query)
    h_orig_latency = (time.perf_counter() - start) * 1000
    h_orig_ids = extract_hybrid_ids(h_orig_context, top_k=TOP_K)

    # 4. Reranked Hybrid GraphRAG
    start = time.perf_counter()
    h_rerank_context = reranked_hybrid_retriever.retrieve(query)
    h_rerank_latency = (time.perf_counter() - start) * 1000
    h_rerank_ids = extract_hybrid_ids(h_rerank_context, top_k=TOP_K)

    # Find target rank in Original vs Reranked
    orig_rank = None
    for r, tid in enumerate(h_orig_ids, start=1):
        if tid in expected_ids:
            orig_rank = r
            break

    rerank_rank = None
    for r, tid in enumerate(h_rerank_ids, start=1):
        if tid in expected_ids:
            rerank_rank = r
            break

    # TASK 9 Explicit Debugging Output
    print(f"\nQUERY {query_id}")
    print(f"ORIGINAL HYBRID TOP-5: {h_orig_ids}")
    print(f"RERANKED HYBRID TOP-5: {h_rerank_ids}")
    print(f"EXPECTED: {sorted(expected_ids)}")
    print(f"Original rank: {orig_rank if orig_rank else 'N/A (>5)'}")
    print(f"Reranked rank: {rerank_rank if rerank_rank else 'N/A (>5)'}")

    methods = {
        "vector": {"ids": v_ids, "latency_ms": v_latency},
        "graph": {"ids": g_ids, "latency_ms": g_latency},
        "original_hybrid": {"ids": h_orig_ids, "latency_ms": h_orig_latency},
        "reranked_hybrid": {"ids": h_rerank_ids, "latency_ms": h_rerank_latency}
    }

    evaluation = {}
    for m, d in methods.items():
        m_ids = d["ids"]
        evaluation[m] = {
            "retrieved_ids": m_ids,
            "precision_at_5": precision_at_k(m_ids, expected_ids, TOP_K),
            "recall_at_5": recall_at_k(m_ids, expected_ids, TOP_K),
            "mrr": reciprocal_rank(m_ids, expected_ids),
            "latency_ms": round(d["latency_ms"], 3)
        }

    return {
        "id": query_id,
        "query": query,
        "expected_mitre_ids": list(expected_ids),
        "results": evaluation
    }


# ============================================================
# SUMMARY CALCULATION
# ============================================================

def calculate_summary(results):
    summary = {}
    methods = ["vector", "graph", "original_hybrid", "reranked_hybrid"]

    for method in methods:
        records = [item["results"][method] for item in results]
        count = len(records)
        if count == 0:
            continue

        summary[method] = {
            "queries": count,
            "mean_precision_at_5": round(sum(r["precision_at_5"] for r in records) / count, 4),
            "mean_recall_at_5": round(sum(r["recall_at_5"] for r in records) / count, 4),
            "mean_mrr": round(sum(r["mrr"] for r in records) / count, 4),
            "mean_latency_ms": round(sum(r["latency_ms"] for r in records) / count, 3)
        }

    return summary


# ============================================================
# MAIN EXPERIMENT
# ============================================================

def main():
    print()
    print("#" * 70)
    print("# GRAPH-AWARE HYBRID RERANKING EXPERIMENT EVALUATION")
    print("#" * 70)

    benchmark = load_benchmark()
    print(f"\nBenchmark queries: {len(benchmark)}")
    print(f"Top-K: {TOP_K}\n")

    vector_retriever = VectorRetriever()
    graph_retriever = GraphBaseline(NEO4J_URI, NEO4J_USERNAME, NEO4J_PASSWORD, NEO4J_DATABASE)
    orig_hybrid_retriever = HybridRetriever(vector_top_k=TOP_K, graph_limit=10)
    reranked_hybrid_retriever = ExperimentalHybridReranker(
        vector_top_k=TOP_K,
        graph_limit=10,
        candidate_pool_size=10
    )

    results = []

    try:
        for item in benchmark:
            res = evaluate_query(
                item,
                vector_retriever,
                graph_retriever,
                orig_hybrid_retriever,
                reranked_hybrid_retriever
            )
            results.append(res)
    finally:
        graph_retriever.close()
        orig_hybrid_retriever.close()
        reranked_hybrid_retriever.close()

    summary = calculate_summary(results)

    # Save to separate result files
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with open(RESULT_FILE, "w", encoding="utf-8") as file:
        json.dump(results, file, indent=2, ensure_ascii=False)

    with open(SUMMARY_FILE, "w", encoding="utf-8") as file:
        json.dump(summary, file, indent=2, ensure_ascii=False)

    # Print Comparison Table
    print()
    print("=" * 75)
    print("EXPERIMENTAL RERANKING RETRIEVAL EVALUATION")
    print("=" * 75)
    print(f"{'Method':<22}{'P@5':<12}{'R@5':<12}{'MRR':<12}{'Latency(ms)':<15}")
    print("-" * 75)

    for method, values in summary.items():
        print(
            f"{method:<22}"
            f"{values['mean_precision_at_5']:<12.4f}"
            f"{values['mean_recall_at_5']:<12.4f}"
            f"{values['mean_mrr']:<12.4f}"
            f"{values['mean_latency_ms']:<15.3f}"
        )

    print("=" * 75)

    # Calculate Deltas
    orig = summary["original_hybrid"]
    rerank = summary["reranked_hybrid"]

    d_p = rerank["mean_precision_at_5"] - orig["mean_precision_at_5"]
    d_r = rerank["mean_recall_at_5"] - orig["mean_recall_at_5"]
    d_mrr = rerank["mean_mrr"] - orig["mean_mrr"]
    d_lat = rerank["mean_latency_ms"] - orig["mean_latency_ms"]

    print("\nRERANKED HYBRID vs ORIGINAL HYBRID:")
    print(f"  Δ Precision@5: {d_p:+.4f}")
    print(f"  Δ Recall@5:    {d_r:+.4f}")
    print(f"  Δ MRR:         {d_mrr:+.4f}")
    print(f"  Δ Latency:     {d_lat:+.3f} ms")
    print()
    print(f"Results saved to: {RESULT_FILE}")
    print(f"Summary saved to: {SUMMARY_FILE}\n")


if __name__ == "__main__":
    main()
