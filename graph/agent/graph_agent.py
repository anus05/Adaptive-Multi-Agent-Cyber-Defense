import json
import sys
from pathlib import Path


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Add project root to Python path.
# This allows imports such as:
#
# from graph.retrieval.hybrid_retriever import HybridRetriever
#
# even when this file is executed directly.

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# IMPORTS
# ============================================================

from graph.retrieval.hybrid_retriever import HybridRetriever
from graph.retrieval.context_builder import (
    GraphRAGContextBuilder
)


# ============================================================
# PROJECT PATHS
# ============================================================

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "retrieval"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "graph_agent_result.json"
)


# ============================================================
# GRAPH AGENT
# ============================================================

class GraphAgent:

    def __init__(
        self,
        vector_top_k=5,
        graph_limit=10
    ):
        """
        Graph Agent

        Responsibilities:
        -----------------
        1. Receive cybersecurity query
        2. Perform Hybrid GraphRAG retrieval
        3. Build structured evidence
        4. Produce LLM-ready context

        The Graph Agent does NOT:
        - execute security actions
        - block IP addresses
        - kill processes
        - modify systems
        - perform autonomous response
        """

        print("Initializing Graph Agent...")

        # ----------------------------------------------------
        # Hybrid retrieval
        # ----------------------------------------------------

        self.retriever = HybridRetriever(
            vector_top_k=vector_top_k,
            graph_limit=graph_limit
        )

        # ----------------------------------------------------
        # Context builder
        # ----------------------------------------------------

        self.context_builder = (
            GraphRAGContextBuilder(
                max_vector_results=vector_top_k,
                max_graph_entities=vector_top_k,
                max_neighbors=graph_limit,
                max_paths=graph_limit
            )
        )

        print("Graph Agent initialized")


    # ========================================================
    # ANALYZE
    # ========================================================

    def analyze(self, query):
        """
        Main Graph Agent interface.

        Example:

            result = agent.analyze(
                "techniques used by attackers for command execution"
            )
        """

        # ----------------------------------------------------
        # Validate query
        # ----------------------------------------------------

        if not query or not query.strip():

            raise ValueError(
                "Query cannot be empty."
            )

        query = query.strip()

        print("\n" + "=" * 70)
        print("GRAPH AGENT ANALYSIS")
        print("=" * 70)

        print(
            f"\nQuery: {query}"
        )

        # ====================================================
        # STEP 1 — HYBRID RETRIEVAL
        # ====================================================

        print(
            "\n[1] Running Hybrid GraphRAG retrieval..."
        )

        hybrid_context = (
            self.retriever.retrieve(
                query
            )
        )

        # ====================================================
        # STEP 2 — BUILD CONTEXT
        # ====================================================

        print(
            "\n[2] Building LLM-ready evidence..."
        )

        final_context = (
            self.context_builder.build(
                hybrid_context
            )
        )

        # ====================================================
        # STEP 3 — EXTRACT CONTEXT
        # ====================================================

        vector_context = (
            final_context.get(
                "vector_context",
                []
            )
        )

        graph_context = (
            final_context.get(
                "graph_context",
                []
            )
        )

        evidence = (
            final_context.get(
                "evidence",
                []
            )
        )

        llm_context = (
            final_context.get(
                "llm_context",
                ""
            )
        )

        # ====================================================
        # STEP 4 — EXTRACT TECHNIQUES
        # ====================================================

        techniques = []

        seen_techniques = set()

        for item in vector_context:

            name = item.get(
                "name"
            )

            mitre_id = item.get(
                "mitre_id"
            )

            if not name:
                continue

            key = (
                mitre_id
                or name
            )

            if key in seen_techniques:
                continue

            seen_techniques.add(
                key
            )

            techniques.append(
                {
                    "name": name,

                    "mitre_id": mitre_id,

                    "type": item.get(
                        "type"
                    ),

                    "description": item.get(
                        "description"
                    ),

                    "retrieval_rank": item.get(
                        "rank"
                    ),

                    "distance": item.get(
                        "distance"
                    )
                }
            )

        # ====================================================
        # STEP 5 — EXTRACT RELATIONSHIPS
        # ====================================================

        relationships = []

        for item in graph_context:

            entity_name = item.get(
                "entity"
            )

            # ------------------------------------------------
            # Outgoing relationships
            # ------------------------------------------------

            for neighbor in item.get(
                "neighbors",
                []
            ):

                relationships.append(
                    {
                        "source": entity_name,

                        "relationship": neighbor,

                        "direction": "OUTGOING"
                    }
                )

            # ------------------------------------------------
            # Incoming relationships
            # ------------------------------------------------

            for neighbor in item.get(
                "reverse_neighbors",
                []
            ):

                relationships.append(
                    {
                        "source": entity_name,

                        "relationship": neighbor,

                        "direction": "INCOMING"
                    }
                )

        # ====================================================
        # STEP 6 — EXTRACT ATTACK PATHS
        # ====================================================

        attack_paths = []

        for item in graph_context:

            entity_name = item.get(
                "entity"
            )

            paths = item.get(
                "paths",
                []
            )

            for path in paths:

                attack_paths.append(
                    {
                        "start_entity": (
                            entity_name
                        ),

                        "path": path
                    }
                )

        # ====================================================
        # STEP 7 — BUILD RESULT
        # ====================================================

        result = {

            # ------------------------------------------------
            # Agent information
            # ------------------------------------------------

            "agent": "GraphAgent",

            "version": "1.0",

            # ------------------------------------------------
            # Query
            # ------------------------------------------------

            "query": query,

            # ------------------------------------------------
            # Retrieval configuration
            # ------------------------------------------------

            "retrieval": {

                "strategy": (
                    "Hybrid GraphRAG"
                ),

                "vector_database": (
                    "ChromaDB"
                ),

                "knowledge_graph": (
                    "Neo4j"
                ),

                "vector_top_k": (
                    self.retriever.vector_top_k
                ),

                "graph_expansion_hops": 3

            },

            # ------------------------------------------------
            # Retrieved cybersecurity knowledge
            # ------------------------------------------------

            "techniques": techniques,

            "relationships": relationships,

            "attack_paths": attack_paths,

            # ------------------------------------------------
            # Evidence
            # ------------------------------------------------

            "evidence": evidence,

            # ------------------------------------------------
            # LLM-ready context
            # ------------------------------------------------

            "llm_context": llm_context,

            # ------------------------------------------------
            # Statistics
            # ------------------------------------------------

            "statistics": {

                "vector_results": (
                    len(vector_context)
                ),

                "graph_entities": (
                    len(graph_context)
                ),

                "techniques": (
                    len(techniques)
                ),

                "relationships": (
                    len(relationships)
                ),

                "attack_paths": (
                    len(attack_paths)
                ),

                "evidence_items": (
                    len(evidence)
                ),

                "llm_context_characters": (
                    len(llm_context)
                )
            }
        }

        return result


    # ========================================================
    # SAVE RESULT
    # ========================================================

    def save_result(
        self,
        result,
        output_file=OUTPUT_FILE
    ):

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                result,
                f,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        return output_file


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("GRAPH AGENT TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # Test query
    # --------------------------------------------------------

    query = (
        "techniques used by attackers "
        "for command execution"
    )

    # --------------------------------------------------------
    # Initialize Graph Agent
    # --------------------------------------------------------

    agent = GraphAgent(
        vector_top_k=5,
        graph_limit=10
    )

    # --------------------------------------------------------
    # Analyze
    # --------------------------------------------------------

    result = agent.analyze(
        query
    )

    # ========================================================
    # RETRIEVED TECHNIQUES
    # ========================================================

    print("\n")
    print("-" * 70)
    print("RETRIEVED TECHNIQUES")
    print("-" * 70)

    for i, technique in enumerate(
        result["techniques"],
        start=1
    ):

        print(
            f"{i}. "
            f"{technique.get('name')} "
            f"("
            f"{technique.get('mitre_id')}"
            f")"
        )

    # ========================================================
    # GRAPH RELATIONSHIPS
    # ========================================================

    print("\n")
    print("-" * 70)
    print("GRAPH RELATIONSHIPS")
    print("-" * 70)

    print(
        f"Total relationships: "
        f"{len(result['relationships'])}"
    )

    for relationship in result[
        "relationships"
    ][:10]:

        print(
            f"- "
            f"{relationship.get('source')} "
            f"-> "
            f"{relationship.get('relationship')} "
            f"["
            f"{relationship.get('direction')}"
            f"]"
        )

    # ========================================================
    # ATTACK PATHS
    # ========================================================

    print("\n")
    print("-" * 70)
    print("MULTI-HOP ATTACK PATHS")
    print("-" * 70)

    print(
        f"Total paths: "
        f"{len(result['attack_paths'])}"
    )

    for path in result[
        "attack_paths"
    ][:10]:

        print(
            f"- "
            f"{path.get('start_entity')}: "
            f"{path.get('path')}"
        )

    # ========================================================
    # EVIDENCE
    # ========================================================

    print("\n")
    print("-" * 70)
    print("EVIDENCE")
    print("-" * 70)

    print(
        f"Evidence items: "
        f"{result['statistics']['evidence_items']}"
    )

    # ========================================================
    # STATISTICS
    # ========================================================

    print("\n")
    print("-" * 70)
    print("GRAPH AGENT STATISTICS")
    print("-" * 70)

    for key, value in result[
        "statistics"
    ].items():

        print(
            f"{key}: {value}"
        )

    # ========================================================
    # SAVE RESULT
    # ========================================================

    output = agent.save_result(
        result
    )

    print("\n")
    print("=" * 70)
    print("GRAPH AGENT COMPLETE")
    print("=" * 70)

    print(
        "\nSaved result to:"
    )

    print(output)