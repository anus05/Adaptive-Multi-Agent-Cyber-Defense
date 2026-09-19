import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


# ============================================================
# IMPORTS
# ============================================================

from graph.retrieval.graph_retriever import GraphRetriever
from graph.retrieval.vector_store import VectorStore


# ============================================================
# HYBRID GRAPHRAG RETRIEVER
# ============================================================

class HybridRetriever:
    """
    Hybrid GraphRAG Retriever.

    Retrieval pipeline:

        Query
          |
          +--> Vector Retrieval
          |
          +--> Graph Retrieval
          |
          +--> RRF Rank Fusion
                    |
                    v
              Hybrid Top-K
                    |
                    v
              Graph Expansion
                    |
                    v
                 Evidence
    """

    # ========================================================
    # INITIALIZATION
    # ========================================================

    def __init__(
        self,
        vector_top_k: int = 5,
        graph_limit: int = 10,
        fusion_top_k: int = 5,
        rrf_k: int = 60
    ):
        print(
            "Initializing Hybrid GraphRAG Retriever..."
        )

        self.vector_top_k = vector_top_k
        self.graph_limit = graph_limit
        self.fusion_top_k = fusion_top_k
        self.rrf_k = rrf_k

        # ----------------------------------------------------
        # Graph Retriever
        # ----------------------------------------------------

        self.graph = GraphRetriever()

        print(
            "Graph Retriever initialized"
        )

        # ----------------------------------------------------
        # Vector Store
        # ----------------------------------------------------

        self.vector_store = VectorStore()

        print(
            "Vector Store initialized"
        )


    # ========================================================
    # QUERY TERM EXTRACTION
    # ========================================================

    def extract_query_terms(
        self,
        query: str
    ) -> List[str]:
        """
        Extract useful lexical terms from the query.
        """

        stop_words = {
            "what",
            "which",
            "how",
            "can",
            "could",
            "would",
            "does",
            "do",
            "the",
            "a",
            "an",
            "is",
            "are",
            "was",
            "were",
            "be",
            "been",
            "being",
            "used",
            "using",
            "use",
            "attacker",
            "attackers",
            "attack",
            "attacks",
            "technique",
            "techniques",
            "represents",
            "represent",
            "representing",
            "involves",
            "involve",
            "involving",
            "for",
            "to",
            "into",
            "from",
            "by",
            "with",
            "and",
            "or",
            "that",
            "this",
            "these",
            "those",
            "on",
            "of",
            "in",
            "as",
            "their",
            "they",
            "them",
            "through",
            "against",
            "system",
            "systems",
            "activity",
            "activities"
        }

        words = re.findall(
            r"[a-zA-Z0-9.-]+",
            query.lower()
        )

        terms = []

        for word in words:

            if word in stop_words:
                continue

            if len(word) <= 2:
                continue

            if word not in terms:
                terms.append(word)

        return terms


    # ========================================================
    # VECTOR RETRIEVAL
    # ========================================================

    def vector_search(
        self,
        query: str,
        top_k: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Semantic vector retrieval.
        """

        if top_k is None:
            top_k = self.vector_top_k

        results = self.vector_store.search(
            query,
            top_k=top_k
        )

        normalized = []

        for rank, result in enumerate(
            results,
            start=1
        ):

            metadata = result.get("metadata") or {}

            name = (
                result.get("name")
                or metadata.get("name")
                or ""
            )

            mitre_id = (
                result.get("mitre_id")
                or result.get("external_id")
                or metadata.get("mitre_id")
                or metadata.get("external_id")
                or ""
            )

            stix_id = (
                result.get("stix_id")
                or metadata.get("stix_id")
                or ""
            )

            description = (
                result.get("description")
                or metadata.get("description")
                or ""
            )

            object_type = (
                result.get("type")
                or metadata.get("type")
                or ""
            )

            distance = result.get("distance")
            document = result.get("document", "")

            normalized.append({
                "name": name,
                "mitre_id": mitre_id,
                "stix_id": stix_id,
                "description": description,
                "type": object_type,
                "distance": distance,
                "document": document,
                "rank": rank,
                "source": "vector"
            })

        return normalized


    # ========================================================
    # GRAPH RETRIEVAL
    # ========================================================

    def graph_search(
        self,
        query: str,
        limit: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Lexical retrieval from the Neo4j
        cybersecurity knowledge graph.

        Ground-truth MITRE IDs are NOT used.
        """

        if limit is None:
            limit = self.graph_limit

        terms = self.extract_query_terms(
            query
        )

        if not getattr(self.graph, "driver", None):
            return []

        if not terms:
            return []

        cypher = """
        MATCH (t:Technique)

        WITH
            t,
            toLower(
                coalesce(t.name, "")
            ) AS name,
            toLower(
                coalesce(t.description, "")
            ) AS description

        WITH
            t,
            name,
            description,

            reduce(
                score = 0,
                term IN $terms |

                score +

                CASE

                    WHEN name CONTAINS term
                    THEN 5

                    WHEN description CONTAINS term
                    THEN 1

                    ELSE 0

                END
            ) AS score

        WHERE score > 0

        RETURN
            t.name AS name,
            t.mitre_id AS mitre_id,
            t.stix_id AS stix_id,
            t.description AS description,
            score

        ORDER BY
            score DESC,
            name ASC

        LIMIT $limit
        """

        database = getattr(
            self.graph,
            "database",
            "neo4j"
        )

        results = []

        with self.graph.driver.session(
            database=database
        ) as session:

            records = session.run(
                cypher,
                terms=terms,
                limit=limit
            )

            for rank, record in enumerate(
                records,
                start=1
            ):

                data = record.data()

                results.append({

                    "name":
                        data.get("name"),

                    "mitre_id":
                        data.get("mitre_id"),

                    "stix_id":
                        data.get("stix_id"),

                    "description":
                        data.get("description"),

                    "graph_score":
                        data.get("score", 0),

                    "rank":
                        rank,

                    "source":
                        "graph"
                })

        return results


    # ========================================================
    # RECIPROCAL RANK FUSION
    # ========================================================

    def reciprocal_rank_fusion(
        self,
        vector_results: List[Dict[str, Any]],
        graph_results: List[Dict[str, Any]],
        top_k: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """
        Reciprocal Rank Fusion.

        RRF score:

            score(d) =
                SUM(
                    1 / (k + rank)
                )

        where k = 60 by default.
        """

        if top_k is None:
            top_k = self.fusion_top_k

        fused = {}

        # ----------------------------------------------------
        # Vector results
        # ----------------------------------------------------

        for rank, result in enumerate(
            vector_results,
            start=1
        ):

            mitre_id = result.get(
                "mitre_id"
            )

            if not mitre_id:
                continue

            if mitre_id not in fused:

                fused[mitre_id] = {

                    "name":
                        result.get("name"),

                    "mitre_id":
                        mitre_id,

                    "stix_id":
                        result.get("stix_id"),

                    "description":
                        result.get(
                            "description",
                            ""
                        ),

                    "rrf_score":
                        0.0,

                    "vector_rank":
                        None,

                    "graph_rank":
                        None,

                    "sources":
                        [],

                    "vector_result":
                        result,

                    "graph_result":
                        None
                }

            fused[
                mitre_id
            ][
                "rrf_score"
            ] += (
                1.0
                / (
                    self.rrf_k
                    + rank
                )
            )

            fused[
                mitre_id
            ][
                "vector_rank"
            ] = rank

            if "vector" not in fused[
                mitre_id
            ][
                "sources"
            ]:

                fused[
                    mitre_id
                ][
                    "sources"
                ].append(
                    "vector"
                )

        # ----------------------------------------------------
        # Graph results
        # ----------------------------------------------------

        for rank, result in enumerate(
            graph_results,
            start=1
        ):

            mitre_id = result.get(
                "mitre_id"
            )

            if not mitre_id:
                continue

            if mitre_id not in fused:

                fused[mitre_id] = {

                    "name":
                        result.get("name"),

                    "mitre_id":
                        mitre_id,

                    "stix_id":
                        result.get("stix_id"),

                    "description":
                        result.get(
                            "description",
                            ""
                        ),

                    "rrf_score":
                        0.0,

                    "vector_rank":
                        None,

                    "graph_rank":
                        None,

                    "sources":
                        [],

                    "vector_result":
                        None,

                    "graph_result":
                        result
                }

            else:

                fused[
                    mitre_id
                ][
                    "graph_result"
                ] = result

            fused[
                mitre_id
            ][
                "rrf_score"
            ] += (
                1.0
                / (
                    self.rrf_k
                    + rank
                )
            )

            fused[
                mitre_id
            ][
                "graph_rank"
            ] = rank

            if "graph" not in fused[
                mitre_id
            ][
                "sources"
            ]:

                fused[
                    mitre_id
                ][
                    "sources"
                ].append(
                    "graph"
                )

        # ----------------------------------------------------
        # Sort
        # ----------------------------------------------------

        ranked = sorted(
            fused.values(),
            key=lambda x: (
                -x["rrf_score"],
                -(
                    len(
                        x["sources"]
                    )
                ),
                x.get(
                    "name"
                ) or ""
            )
        )

        # ----------------------------------------------------
        # Add final rank
        # ----------------------------------------------------

        for rank, item in enumerate(
            ranked[:top_k],
            start=1
        ):

            item["hybrid_rank"] = rank

        return ranked[:top_k]


    # ========================================================
    # EXACT GRAPH LOOKUP
    # ========================================================

    def exact_graph_lookup(
        self,
        query: str
    ) -> List[Dict[str, Any]]:
        """
        Try exact entity lookup in Neo4j.
        """

        results = []

        query_clean = query.strip()

        if not query_clean:
            return results

        try:

            entity = self.graph.find_entity(
                query_clean
            )

            if entity:

                results.extend(
                    entity
                )

        except Exception as e:

            print(
                f"Exact graph lookup warning: {e}"
            )

        return results


    # ========================================================
    # GRAPH EXPANSION
    # ========================================================

    def expand_graph(
        self,
        fused_results: List[Dict[str, Any]],
        max_entities: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Expand the top hybrid entities
        using Neo4j relationships.
        """

        graph_entities = []

        for result in fused_results[
            :max_entities
        ]:

            name = result.get(
                "name"
            )

            mitre_id = result.get(
                "mitre_id"
            )

            if not name:
                continue

            entity_data = {

                "name":
                    name,

                "mitre_id":
                    mitre_id,

                "neighbors":
                    [],

                "reverse_neighbors":
                    [],

                "paths":
                    []
            }

            # ------------------------------------------------
            # Outgoing neighbors
            # ------------------------------------------------

            try:

                entity_data[
                    "neighbors"
                ] = self.graph.get_neighbors(
                    name
                )

            except Exception as e:

                print(
                    f"Neighbor lookup warning "
                    f"for {name}: {e}"
                )

            # ------------------------------------------------
            # Incoming neighbors
            # ------------------------------------------------

            try:

                entity_data[
                    "reverse_neighbors"
                ] = self.graph.get_reverse_neighbors(
                    name
                )

            except Exception as e:

                print(
                    f"Reverse neighbor warning "
                    f"for {name}: {e}"
                )

            # ------------------------------------------------
            # Multi-hop paths
            # ------------------------------------------------

            try:

                entity_data[
                    "paths"
                ] = self.graph.get_attack_paths(
                    name,
                    max_hops=3
                )

            except Exception as e:

                print(
                    f"Path lookup warning "
                    f"for {name}: {e}"
                )

            graph_entities.append(
                entity_data
            )

        return graph_entities


    # ========================================================
    # EVIDENCE CONSTRUCTION
    # ========================================================

    def build_evidence(
        self,
        vector_results: List[Dict[str, Any]],
        graph_results: List[Dict[str, Any]],
        fused_results: List[Dict[str, Any]],
        graph_entities: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Construct evidence objects for
        downstream GraphRAG reasoning.
        """

        evidence = []

        # ----------------------------------------------------
        # Vector evidence
        # ----------------------------------------------------

        for result in vector_results:

            evidence.append({

                "evidence_type":
                    "vector_retrieval",

                "source":
                    "ChromaDB",

                "rank":
                    result.get("rank"),

                "mitre_id":
                    result.get("mitre_id"),

                "name":
                    result.get("name"),

                "description":
                    result.get(
                        "description",
                        ""
                    ),

                "distance":
                    result.get(
                        "distance"
                    )
            })

        # ----------------------------------------------------
        # Graph evidence
        # ----------------------------------------------------

        for result in graph_results:

            evidence.append({

                "evidence_type":
                    "graph_retrieval",

                "source":
                    "Neo4j",

                "rank":
                    result.get("rank"),

                "mitre_id":
                    result.get("mitre_id"),

                "name":
                    result.get("name"),

                "description":
                    result.get(
                        "description",
                        ""
                    ),

                "graph_score":
                    result.get(
                        "graph_score"
                    )
            })

        # ----------------------------------------------------
        # Hybrid evidence
        # ----------------------------------------------------

        for result in fused_results:

            evidence.append({

                "evidence_type":
                    "rrf_fusion",

                "source":
                    result.get(
                        "sources",
                        []
                    ),

                "hybrid_rank":
                    result.get(
                        "hybrid_rank"
                    ),

                "rrf_score":
                    result.get(
                        "rrf_score"
                    ),

                "mitre_id":
                    result.get(
                        "mitre_id"
                    ),

                "name":
                    result.get(
                        "name"
                    ),

                "vector_rank":
                    result.get(
                        "vector_rank"
                    ),

                "graph_rank":
                    result.get(
                        "graph_rank"
                    )
            })

        # ----------------------------------------------------
        # Graph expansion evidence
        # ----------------------------------------------------

        for entity in graph_entities:

            name = entity.get(
                "name"
            )

            mitre_id = entity.get(
                "mitre_id"
            )

            # Outgoing
            for neighbor in entity.get(
                "neighbors",
                []
            ):

                evidence.append({

                    "evidence_type":
                        "graph_relationship",

                    "source":
                        "Neo4j",

                    "entity":
                        name,

                    "mitre_id":
                        mitre_id,

                    "relationship":
                        neighbor
                })

            # Incoming
            for neighbor in entity.get(
                "reverse_neighbors",
                []
            ):

                evidence.append({

                    "evidence_type":
                        "reverse_graph_relationship",

                    "source":
                        "Neo4j",

                    "entity":
                        name,

                    "mitre_id":
                        mitre_id,

                    "relationship":
                        neighbor
                })

            # Paths
            for path in entity.get(
                "paths",
                []
            ):

                evidence.append({

                    "evidence_type":
                        "multi_hop_attack_path",

                    "source":
                        "Neo4j",

                    "entity":
                        name,

                    "mitre_id":
                        mitre_id,

                    "path":
                        path
                })

        return evidence


    # ========================================================
    # RETRIEVE
    # ========================================================

    def retrieve(
        self,
        query: str
    ) -> Dict[str, Any]:
        """
        Complete Hybrid GraphRAG retrieval pipeline.
        """

        print(
            "\n"
            + "=" * 70
        )

        print(
            "HYBRID GRAPHRAG WITH RRF RANK FUSION"
        )

        print(
            "=" * 70
        )

        print(
            f"\nQuery: {query}"
        )

        # ====================================================
        # 1. VECTOR RETRIEVAL
        # ====================================================

        print(
            "\n[1] Vector retrieval..."
        )

        vector_results = (
            self.vector_search(
                query,
                self.vector_top_k
            )
        )

        print(
            f"    Retrieved "
            f"{len(vector_results)} "
            f"semantic results"
        )

        # ====================================================
        # 2. GRAPH RETRIEVAL
        # ====================================================

        print(
            "\n[2] Graph retrieval..."
        )

        graph_results = (
            self.graph_search(
                query,
                self.graph_limit
            )
        )

        print(
            f"    Retrieved "
            f"{len(graph_results)} "
            f"graph candidates"
        )

        # ====================================================
        # 3. RRF FUSION
        # ====================================================

        print(
            "\n[3] RRF rank fusion..."
        )

        fused_results = (
            self.reciprocal_rank_fusion(
                vector_results,
                graph_results,
                self.fusion_top_k
            )
        )

        print(
            f"    Final hybrid candidates: "
            f"{len(fused_results)}"
        )

        for result in fused_results:

            print(
                f"    "
                f"{result.get('hybrid_rank')}. "
                f"{result.get('name')} "
                f"({result.get('mitre_id')}) "
                f"score="
                f"{result.get('rrf_score'):.6f} "
                f"sources="
                f"{result.get('sources')}"
            )

        # ====================================================
        # 4. EXACT GRAPH LOOKUP
        # ====================================================

        print(
            "\n[4] Exact graph lookup..."
        )

        exact_graph_match = (
            self.exact_graph_lookup(
                query
            )
        )

        if exact_graph_match:

            print(
                f"    Found "
                f"{len(exact_graph_match)} "
                f"exact graph entities"
            )

        else:

            print(
                "    No exact graph entity found"
            )

        # ====================================================
        # 5. GRAPH EXPANSION
        # ====================================================

        print(
            "\n[5] Graph expansion..."
        )

        graph_entities = (
            self.expand_graph(
                fused_results
            )
        )

        for entity in graph_entities:

            print(
                f"    Expanding: "
                f"{entity.get('name')}"
            )

        # ====================================================
        # 6. EVIDENCE
        # ====================================================

        print(
            "\n[6] Building evidence..."
        )

        evidence = (
            self.build_evidence(
                vector_results,
                graph_results,
                fused_results,
                graph_entities
            )
        )

        # ====================================================
        # FINAL CONTEXT
        # ====================================================

        context = {

            "query":
                query,

            "vector_results":
                vector_results,

            "graph_results":
                graph_results,

            "fused_results":
                fused_results,

            "exact_graph_match":
                exact_graph_match,

            "graph_entities":
                graph_entities,

            "evidence":
                evidence
        }

        # ====================================================
        # SAVE CONTEXT
        # ====================================================

        output_dir = (
            Path(__file__).resolve()
            .parents[2]
            / "data"
            / "retrieval"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        output_file = (
            output_dir
            / "hybrid_context.json"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                context,
                f,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        print(
            "\nFINAL HYBRID RESULTS"
        )

        for result in fused_results:

            print(
                f"{result.get('hybrid_rank')}. "
                f"{result.get('name')} "
                f"({result.get('mitre_id')})"
            )

            print(
                f"   RRF Score: "
                f"{result.get('rrf_score'):.6f}"
            )

            print(
                f"   Vector Rank: "
                f"{result.get('vector_rank')}"
            )

            print(
                f"   Graph Rank: "
                f"{result.get('graph_rank')}"
            )

            print(
                f"   Sources: "
                f"{result.get('sources')}"
            )

        print(
            "\nHYBRID RETRIEVAL COMPLETE"
        )

        print(
            "Saved context to:"
        )

        print(
            output_file
        )

        return context


    # ========================================================
    # CLOSE
    # ========================================================

    def close(self):

        try:

            self.graph.close()

        except Exception:

            pass
# ============================================================
# MAIN TEST
# ============================================================

if __name__ == "__main__":

    print()
    print("=" * 70)
    print("HYBRID GRAPHRAG RETRIEVER TEST")
    print("=" * 70)

    retriever = HybridRetriever(
        vector_top_k=5,
        graph_limit=10,
        fusion_top_k=5,
        rrf_k=60
    )

    query = "techniques used by attackers for command execution"

    print()
    print("QUERY:")
    print(query)

    print()
    print("Running Hybrid GraphRAG retrieval...")
    print()

    result = retriever.retrieve(query)

    # --------------------------------------------------------
    # VECTOR RESULTS
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("VECTOR RESULTS")
    print("=" * 70)

    for i, item in enumerate(
        result.get("vector_results", []),
        start=1
    ):

        print(
            f"{i}. "
            f"{item.get('name', '')} | "
            f"{item.get('mitre_id', '')} | "
            f"distance={item.get('distance', '')}"
        )


    # --------------------------------------------------------
    # GRAPH RESULTS
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("GRAPH RESULTS")
    print("=" * 70)

    for i, item in enumerate(
        result.get("graph_results", []),
        start=1
    ):

        print(
            f"{i}. "
            f"{item.get('name', '')} | "
            f"{item.get('mitre_id', '')} | "
            f"score={item.get('score', '')}"
        )


    # --------------------------------------------------------
    # FUSED RESULTS
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("RRF FUSED RESULTS")
    print("=" * 70)

    for i, item in enumerate(
        result.get("fused_results", []),
        start=1
    ):

        print(
            f"{i}. "
            f"{item.get('name', '')} | "
            f"{item.get('mitre_id', '')} | "
            f"RRF={item.get('rrf_score', '')} | "
            f"sources={item.get('sources', [])}"
        )


    # --------------------------------------------------------
    # GRAPH ENTITIES
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("GRAPH ENTITIES")
    print("=" * 70)

    print(
        len(
            result.get(
                "graph_entities",
                []
            )
        )
    )


    # --------------------------------------------------------
    # EVIDENCE
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("EVIDENCE")
    print("=" * 70)

    print(
        len(
            result.get(
                "evidence",
                []
            )
        )
    )


    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print()
    print("=" * 70)
    print("HYBRID GRAPHRAG TEST COMPLETED")
    print("=" * 70)

    print()
    print(
        "Context saved to:"
    )

    print(
        "data/retrieval/hybrid_context.json"
    )

    print()