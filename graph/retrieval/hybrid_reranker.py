import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from graph.retrieval.hybrid_retriever import HybridRetriever


# ============================================================
# EXPERIMENTAL GRAPH-AWARE HYBRID RERANKER
# ============================================================

class ExperimentalHybridReranker:
    """
    Experimental Graph-Aware Hybrid Reranker.

    Pipeline:
        1. Vector Retrieval (Semantic)
        2. Graph Retrieval (Lexical Cypher)
        3. RRF Rank Fusion -> Top-10 Candidate Pool
        4. Graph-Aware Reranking over Candidate Pool:
           final_score = (alpha * norm_rrf)
                       + (beta * vector_signal)
                       + (gamma * graph_signal)
                       + (delta * agreement_signal)
                       + (epsilon * evidence_signal)
        5. Final Top-5 Selection & Graph Expansion
    """

    def __init__(
        self,
        vector_top_k: int = 5,
        graph_limit: int = 10,
        candidate_pool_size: int = 10,
        fusion_top_k: int = 5,
        rrf_k: int = 60,
        alpha: float = 0.40,
        beta: float = 0.20,
        gamma: float = 0.15,
        delta: float = 0.15,
        epsilon: float = 0.10
    ):
        print("Initializing Experimental Graph-Aware Hybrid Reranker...")
        self.vector_top_k = vector_top_k
        self.graph_limit = graph_limit
        self.candidate_pool_size = candidate_pool_size
        self.fusion_top_k = fusion_top_k
        self.rrf_k = rrf_k

        # Scoring weights
        self.alpha = alpha      # Normalized RRF score weight
        self.beta = beta        # Vector rank signal weight
        self.gamma = gamma      # Graph rank signal weight
        self.delta = delta      # Cross-channel agreement bonus
        self.epsilon = epsilon  # Graph relationship evidence density weight

        # Delegate underlying retrieval components to base HybridRetriever
        self.base_retriever = HybridRetriever(
            vector_top_k=vector_top_k,
            graph_limit=graph_limit,
            fusion_top_k=candidate_pool_size,
            rrf_k=rrf_k
        )

    # ========================================================
    # RERANK CANDIDATE POOL
    # ========================================================

    def rerank_candidates(
        self,
        candidate_pool: List[Dict[str, Any]],
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Apply transparent graph-aware scoring to candidate pool.
        """
        if not candidate_pool:
            return []

        max_rrf = max((item.get("rrf_score", 0.0) for item in candidate_pool), default=1.0)
        if max_rrf <= 0:
            max_rrf = 1.0

        reranked = []

        for candidate in candidate_pool:
            item = dict(candidate)
            name = item.get("name", "")

            # Signal 1: Normalized RRF Score
            rrf_score = item.get("rrf_score", 0.0)
            norm_rrf = rrf_score / max_rrf

            # Signal 2: Vector Rank Signal
            v_rank = item.get("vector_rank")
            vector_signal = (1.0 / v_rank) if v_rank is not None and v_rank > 0 else 0.0

            # Signal 3: Graph Rank Signal
            g_rank = item.get("graph_rank")
            graph_signal = (1.0 / g_rank) if g_rank is not None and g_rank > 0 else 0.0

            # Signal 4: Cross-Channel Agreement
            sources = item.get("sources", [])
            agreement_signal = 1.0 if ("vector" in sources and "graph" in sources) else 0.0

            # Signal 5: Graph Relationship Evidence Density
            evidence_count = 0
            if name:
                try:
                    neighbors = self.base_retriever.graph.get_neighbors(name)
                    reverse = self.base_retriever.graph.get_reverse_neighbors(name)
                    evidence_count = len(neighbors) + len(reverse)
                except Exception:
                    evidence_count = 0

            evidence_signal = min(evidence_count, 10) / 10.0

            # Composite Reranking Score
            rerank_score = (
                (self.alpha * norm_rrf)
                + (self.beta * vector_signal)
                + (self.gamma * graph_signal)
                + (self.delta * agreement_signal)
                + (self.epsilon * evidence_signal)
            )

            item["rerank_score"] = rerank_score
            item["norm_rrf"] = norm_rrf
            item["vector_signal"] = vector_signal
            item["graph_signal"] = graph_signal
            item["agreement_signal"] = agreement_signal
            item["evidence_signal"] = evidence_signal
            reranked.append(item)

        # Sort pool by rerank_score (descending), source agreement length, and name
        reranked.sort(
            key=lambda x: (
                -x["rerank_score"],
                -len(x.get("sources", [])),
                (x.get("name") or "").lower()
            )
        )

        top_reranked = reranked[:top_k]
        for rank, item in enumerate(top_reranked, start=1):
            item["hybrid_rank"] = rank

        return top_reranked

    # ========================================================
    # RETRIEVE & RERANK
    # ========================================================

    def retrieve(self, query: str) -> Dict[str, Any]:
        """
        Execute vector + graph retrieval, RRF fusion, graph-aware reranking,
        and evidence construction.
        """
        # 1. Vector Search
        vector_results = self.base_retriever.vector_search(query, self.vector_top_k)

        # 2. Graph Search
        graph_results = self.base_retriever.graph_search(query, self.graph_limit)

        # 3. Initial RRF Fusion (Candidate pool size = 10)
        candidate_pool = self.base_retriever.reciprocal_rank_fusion(
            vector_results,
            graph_results,
            top_k=self.candidate_pool_size
        )

        # Original Top-5 for baseline comparison
        original_fused_top5 = candidate_pool[:self.fusion_top_k]

        # 4. Graph-Aware Reranking
        reranked_fused_top5 = self.rerank_candidates(
            candidate_pool,
            top_k=self.fusion_top_k
        )

        # 5. Exact Graph Lookup
        exact_graph_match = self.base_retriever.exact_graph_lookup(query)

        # 6. Graph Expansion for Reranked Top-5
        graph_entities = self.base_retriever.expand_graph(reranked_fused_top5)

        # 7. Evidence Construction
        evidence = self.base_retriever.build_evidence(
            vector_results,
            graph_results,
            reranked_fused_top5,
            graph_entities
        )

        return {
            "query": query,
            "vector_results": vector_results,
            "graph_results": graph_results,
            "candidate_pool": candidate_pool,
            "original_fused_results": original_fused_top5,
            "fused_results": reranked_fused_top5,
            "exact_graph_match": exact_graph_match,
            "graph_entities": graph_entities,
            "evidence": evidence
        }

    def close(self):
        try:
            self.base_retriever.close()
        except Exception:
            pass


# ============================================================
# MAIN TEST
# ============================================================

def main():
    print()
    print("=" * 70)
    print("EXPERIMENTAL HYBRID RERANKER TEST")
    print("=" * 70)

    reranker = ExperimentalHybridReranker()
    query = "techniques used by attackers for command execution"
    res = reranker.retrieve(query)

    print("\nORIGINAL FUSED TOP-5:")
    for item in res["original_fused_results"]:
        print(f"  {item.get('name')} ({item.get('mitre_id')}) score={item.get('rrf_score'):.6f}")

    print("\nRERANKED FUSED TOP-5:")
    for item in res["fused_results"]:
        print(f"  {item.get('name')} ({item.get('mitre_id')}) rerank_score={item.get('rerank_score'):.4f}")

    reranker.close()
    print("\n[OK] Reranker test completed")


if __name__ == "__main__":
    main()
