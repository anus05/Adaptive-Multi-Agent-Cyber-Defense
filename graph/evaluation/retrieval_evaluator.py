import json
import os
import time
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

from graph.retrieval.vector_retriever import VectorRetriever
from graph.retrieval.hybrid_retriever import HybridRetriever


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
    / "retrieval_results.json"
)

SUMMARY_FILE = (
    OUTPUT_DIR
    / "retrieval_summary.json"
)


# ============================================================
# CONFIGURATION
# ============================================================

TOP_K = 5


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv(
    PROJECT_ROOT / ".env"
)


NEO4J_URI = os.getenv(
    "NEO4J_URI"
)

NEO4J_USERNAME = os.getenv(
    "NEO4J_USERNAME"
)

NEO4J_PASSWORD = os.getenv(
    "NEO4J_PASSWORD"
)

NEO4J_DATABASE = os.getenv(
    "NEO4J_DATABASE",
    "neo4j"
)


# ============================================================
# LOAD BENCHMARK
# ============================================================

def load_benchmark():

    if not BENCHMARK_FILE.exists():

        raise FileNotFoundError(
            f"Benchmark file not found:\n"
            f"{BENCHMARK_FILE}"
        )

    with open(
        BENCHMARK_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# GRAPH BASELINE
# ============================================================

class GraphBaseline:

    def __init__(
        self,
        uri,
        username,
        password,
        database
    ):

        print(
            "Initializing Graph Baseline..."
        )

        self.driver = GraphDatabase.driver(
            uri,
            auth=(
                username,
                password
            )
        )

        self.database = database

        self.driver.verify_connectivity()

        print(
            "Graph Baseline connected to Neo4j"
        )


    # ========================================================
    # SEARCH
    # ========================================================

    def search(
        self,
        query,
        top_k=5
    ):

        """
        Lexical graph retrieval baseline.

        Searches Technique nodes using words from
        the query.

        Ground-truth MITRE IDs are NOT used here.
        """

        words = [
            word.strip().lower()
            for word in query.split()
            if len(word.strip()) >= 4
        ]


        if not words:

            return []


        conditions = []

        for index in range(
            len(words)
        ):

            conditions.append(
                f"""
                (
                    toLower(
                        coalesce(
                            n.name,
                            ''
                        )
                    ) CONTAINS $word{index}

                    OR

                    toLower(
                        coalesce(
                            n.description,
                            ''
                        )
                    ) CONTAINS $word{index}
                )
                """
            )


        where_clause = " OR ".join(
            conditions
        )


        cypher = f"""
        MATCH (n:Technique)

        WHERE {where_clause}

        WITH
            n,
            reduce(
                score = 0,
                word IN $words |

                score +

                CASE

                    WHEN toLower(
                        coalesce(
                            n.name,
                            ''
                        )
                    ) CONTAINS word

                    THEN 3

                    WHEN toLower(
                        coalesce(
                            n.description,
                            ''
                        )
                    ) CONTAINS word

                    THEN 1

                    ELSE 0

                END

            ) AS lexical_score

        RETURN
            n.name AS name,
            n.mitre_id AS mitre_id,
            n.description AS description,
            lexical_score

        ORDER BY
            lexical_score DESC,
            name ASC

        LIMIT $top_k
        """


        parameters = {
            "words": words,
            "top_k": top_k
        }


        for index, word in enumerate(
            words
        ):

            parameters[
                f"word{index}"
            ] = word


        with self.driver.session(
            database=self.database
        ) as session:

            result = session.run(
                cypher,
                **parameters
            )

            records = list(result)


        formatted = []


        for rank, record in enumerate(
            records,
            start=1
        ):

            formatted.append(
                {
                    "rank": rank,
                    "name": record["name"],
                    "mitre_id": record["mitre_id"],
                    "lexical_score": record[
                        "lexical_score"
                    ]
                }
            )


        return formatted


    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        self.driver.close()


# ============================================================
# PRECISION@K
# ============================================================

def precision_at_k(
    retrieved_ids,
    expected_ids,
    k
):

    retrieved = retrieved_ids[:k]


    if not retrieved:

        return 0.0


    hits = sum(
        1
        for item in retrieved
        if item in expected_ids
    )


    return hits / k


# ============================================================
# RECALL@K
# ============================================================

def recall_at_k(
    retrieved_ids,
    expected_ids,
    k
):

    if not expected_ids:

        return 0.0


    retrieved = set(
        retrieved_ids[:k]
    )


    hits = len(
        retrieved.intersection(
            expected_ids
        )
    )


    return hits / len(
        expected_ids
    )


# ============================================================
# MRR
# ============================================================

def reciprocal_rank(
    retrieved_ids,
    expected_ids
):

    for rank, item in enumerate(
        retrieved_ids,
        start=1
    ):

        if item in expected_ids:

            return 1.0 / rank


    return 0.0


# ============================================================
# VECTOR RESULT IDs
# ============================================================

def extract_vector_ids(
    results,
    top_k=TOP_K
):
    ids = []

    for result in results[:top_k]:
        metadata = result.get(
            "metadata"
        ) or {}

        mitre_id = (
            result.get("mitre_id")
            or result.get("external_id")
            or metadata.get("mitre_id")
            or metadata.get("external_id")
        )

        if mitre_id and mitre_id not in ids:
            ids.append(mitre_id)

    return ids[:top_k]


# ============================================================
# HYBRID RESULT IDs
# ============================================================

def extract_hybrid_ids(
    context,
    top_k=TOP_K
):
    fused_results = context.get(
        "fused_results",
        []
    )

    ids = []

    for item in fused_results[:top_k]:
        mitre_id = (
            item.get("mitre_id")
            or item.get("external_id")
        )

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
    hybrid_retriever
):

    query = benchmark_item[
        "query"
    ]


    expected_ids = set(
        benchmark_item[
            "expected_mitre_ids"
        ]
    )


    print()
    print(
        "=" * 70
    )

    print(
        f"{benchmark_item['id']}: {query}"
    )

    print(
        f"Expected MITRE IDs: "
        f"{sorted(expected_ids)}"
    )

    print(
        "=" * 70
    )


    # ========================================================
    # VECTOR RETRIEVAL
    # ========================================================

    print()
    print(
        "[1] Vector Retrieval..."
    )


    start = time.perf_counter()


    vector_results = (
        vector_retriever.search(
            query,
            top_k=TOP_K
        )
    )


    vector_latency = (
        time.perf_counter()
        - start
    ) * 1000


    vector_ids = extract_vector_ids(
        vector_results,
        top_k=TOP_K
    )


    # ========================================================
    # GRAPH RETRIEVAL
    # ========================================================

    print(
        "[2] Graph Retrieval..."
    )


    start = time.perf_counter()


    graph_results = (
        graph_retriever.search(
            query,
            top_k=TOP_K
        )
    )


    graph_latency = (
        time.perf_counter()
        - start
    ) * 1000


    graph_ids = [
        result["mitre_id"]
        for result in graph_results[:TOP_K]
        if result.get("mitre_id")
    ][:TOP_K]


    # ========================================================
    # HYBRID GRAPHRAG
    # ========================================================

    print(
        "[3] Hybrid GraphRAG..."
    )


    start = time.perf_counter()


    hybrid_context = (
        hybrid_retriever.retrieve(
            query
        )
    )


    hybrid_latency = (
        time.perf_counter()
        - start
    ) * 1000


    hybrid_ids = extract_hybrid_ids(
        hybrid_context,
        top_k=TOP_K
    )

    print(f"\nVECTOR EVALUATED TOP-5: {vector_ids}")
    print(f"GRAPH EVALUATED TOP-5:  {graph_ids}")
    print(f"HYBRID EVALUATED TOP-5: {hybrid_ids}")


    # ========================================================
    # EVALUATE METHODS
    # ========================================================

    methods = {

        "vector": {
            "ids": vector_ids,
            "latency_ms": vector_latency
        },

        "graph": {
            "ids": graph_ids,
            "latency_ms": graph_latency
        },

        "hybrid_graphrag": {
            "ids": hybrid_ids,
            "latency_ms": hybrid_latency
        }
    }


    evaluation = {}


    for method, data in methods.items():

        ids = data["ids"]


        evaluation[method] = {

            "retrieved_ids": ids,

            "precision_at_5":
                precision_at_k(
                    ids,
                    expected_ids,
                    TOP_K
                ),

            "recall_at_5":
                recall_at_k(
                    ids,
                    expected_ids,
                    TOP_K
                ),

            "mrr":
                reciprocal_rank(
                    ids,
                    expected_ids
                ),

            "latency_ms":
                round(
                    data["latency_ms"],
                    3
                )
        }


        print()
        print(
            method.upper()
        )

        print(
            f"  Retrieved: {ids}"
        )

        print(
            f"  Precision@5: "
            f"{evaluation[method]['precision_at_5']:.4f}"
        )

        print(
            f"  Recall@5: "
            f"{evaluation[method]['recall_at_5']:.4f}"
        )

        print(
            f"  MRR: "
            f"{evaluation[method]['mrr']:.4f}"
        )

        print(
            f"  Latency: "
            f"{evaluation[method]['latency_ms']:.3f} ms"
        )


    return {

        "id":
            benchmark_item["id"],

        "query":
            query,

        "expected_mitre_ids":
            list(expected_ids),

        "results":
            evaluation
    }


# ============================================================
# SUMMARY
# ============================================================

def calculate_summary(
    results
):

    summary = {}


    for method in [
        "vector",
        "graph",
        "hybrid_graphrag"
    ]:

        records = [
            item["results"][method]
            for item in results
        ]


        count = len(records)


        if count == 0:

            continue


        summary[method] = {

            "queries":
                count,

            "mean_precision_at_5":
                round(
                    sum(
                        r[
                            "precision_at_5"
                        ]
                        for r in records
                    ) / count,
                    4
                ),

            "mean_recall_at_5":
                round(
                    sum(
                        r[
                            "recall_at_5"
                        ]
                        for r in records
                    ) / count,
                    4
                ),

            "mean_mrr":
                round(
                    sum(
                        r["mrr"]
                        for r in records
                    ) / count,
                    4
                ),

            "mean_latency_ms":
                round(
                    sum(
                        r["latency_ms"]
                        for r in records
                    ) / count,
                    3
                )
        }


    return summary


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print(
        "#" * 70
    )

    print(
        "# MEMBER 2 — GRAPHRAG RETRIEVAL EVALUATION"
    )

    print(
        "#" * 70
    )


    # --------------------------------------------------------
    # Load benchmark
    # --------------------------------------------------------

    benchmark = load_benchmark()


    print()
    print(
        f"Benchmark queries: "
        f"{len(benchmark)}"
    )

    print(
        f"Top-K: {TOP_K}"
    )


    # --------------------------------------------------------
    # Initialize Vector Retriever
    # --------------------------------------------------------

    print()
    print(
        "Initializing Vector Retriever..."
    )


    vector_retriever = (
        VectorRetriever()
    )


    # --------------------------------------------------------
    # Initialize Graph Baseline
    # --------------------------------------------------------

    graph_retriever = (
        GraphBaseline(
            NEO4J_URI,
            NEO4J_USERNAME,
            NEO4J_PASSWORD,
            NEO4J_DATABASE
        )
    )


    # --------------------------------------------------------
    # Initialize Hybrid GraphRAG
    # --------------------------------------------------------

    print()
    print(
        "Initializing Hybrid GraphRAG..."
    )


    hybrid_retriever = (
        HybridRetriever(
            vector_top_k=TOP_K,
            graph_limit=10
        )
    )


    results = []


    try:

        # ----------------------------------------------------
        # Run benchmark
        # ----------------------------------------------------

        for item in benchmark:

            result = evaluate_query(
                item,
                vector_retriever,
                graph_retriever,
                hybrid_retriever
            )


            results.append(
                result
            )


    finally:

        graph_retriever.close()


    # --------------------------------------------------------
    # Calculate summary
    # --------------------------------------------------------

    summary = calculate_summary(
        results
    )


    # --------------------------------------------------------
    # Create output directory
    # --------------------------------------------------------

    OUTPUT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    # --------------------------------------------------------
    # Save detailed results
    # --------------------------------------------------------

    with open(
        RESULT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            results,
            file,
            indent=2,
            ensure_ascii=False
        )


    # --------------------------------------------------------
    # Save summary
    # --------------------------------------------------------

    with open(
        SUMMARY_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            summary,
            file,
            indent=2,
            ensure_ascii=False
        )


    # ========================================================
    # FINAL TABLE
    # ========================================================

    print()
    print()
    print(
        "=" * 70
    )

    print(
        "FINAL RETRIEVAL EVALUATION"
    )

    print(
        "=" * 70
    )

    print()


    print(
        f"{'Method':<22}"
        f"{'P@5':<12}"
        f"{'R@5':<12}"
        f"{'MRR':<12}"
        f"{'Latency(ms)':<15}"
    )


    print(
        "-" * 70
    )


    for method, values in summary.items():

        print(
            f"{method:<22}"
            f"{values['mean_precision_at_5']:<12.4f}"
            f"{values['mean_recall_at_5']:<12.4f}"
            f"{values['mean_mrr']:<12.4f}"
            f"{values['mean_latency_ms']:<15.3f}"
        )


    print(
        "=" * 70
    )


    print()
    print(
        "Detailed results saved to:"
    )

    print(
        RESULT_FILE
    )


    print()
    print(
        "Summary saved to:"
    )

    print(
        SUMMARY_FILE
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()