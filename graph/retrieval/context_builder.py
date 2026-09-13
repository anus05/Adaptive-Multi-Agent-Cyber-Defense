import json
from pathlib import Path


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "retrieval"
    / "hybrid_context.json"
)

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
    / "llm_context.json"
)


# ============================================================
# CONTEXT BUILDER
# ============================================================

class GraphRAGContextBuilder:

    def __init__(
        self,
        max_vector_results=5,
        max_graph_entities=5,
        max_neighbors=10,
        max_paths=10
    ):

        self.max_vector_results = (
            max_vector_results
        )

        self.max_graph_entities = (
            max_graph_entities
        )

        self.max_neighbors = (
            max_neighbors
        )

        self.max_paths = (
            max_paths
        )

    # ========================================================
    # LOAD HYBRID CONTEXT
    # ========================================================

    def load_context(self, input_file=INPUT_FILE):

        with open(
            input_file,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    # ========================================================
    # CLEAN VECTOR RESULTS
    # ========================================================

    def build_vector_context(
        self,
        vector_results
    ):

        cleaned = []

        for rank, result in enumerate(
            vector_results[
                :self.max_vector_results
            ],
            start=1
        ):

            metadata = result.get(
                "metadata"
            ) or {}

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

            object_type = (
                result.get("type")
                or metadata.get("type")
                or ""
            )

            description = (
                result.get("description")
                or metadata.get("description")
                or result.get("document", "")
            )

            cleaned.append(
                {
                    "rank": rank,
                    "name": name,
                    "type": object_type,
                    "mitre_id": mitre_id,
                    "distance": result.get("distance"),
                    "description": description
                }
            )

        return cleaned

    # ========================================================
    # CLEAN GRAPH ENTITY
    # ========================================================

    def build_graph_context(
        self,
        graph_entities
    ):

        cleaned = []

        for item in graph_entities[
            :self.max_graph_entities
        ]:

            if not isinstance(
                item,
                dict
            ):
                continue

            entity_name = (
                item.get("entity")
                or item.get("name")
            )

            if not entity_name:
                continue

            entity_data = item.get(
                "entity_data",
                []
            )

            if not entity_data and ("name" in item or "mitre_id" in item):
                entity_data = [item]
            elif not isinstance(
                entity_data,
                list
            ):
                entity_data = [
                    entity_data
                ]

            entities = []

            for entity in entity_data:

                if not isinstance(
                    entity,
                    dict
                ):
                    continue

                entities.append(
                    {
                        "name": entity.get(
                            "name"
                        ),

                        "mitre_id": entity.get(
                            "mitre_id"
                        ),

                        "stix_id": entity.get(
                            "stix_id"
                        ),

                        "description": entity.get(
                            "description"
                        ),

                        "tactics": entity.get(
                            "tactics"
                        )
                    }
                )

            cleaned.append(
                {
                    "entity": entity_name,

                    "entities": entities,

                    "neighbors": item.get(
                        "neighbors",
                        []
                    )[
                        :self.max_neighbors
                    ],

                    "reverse_neighbors": item.get(
                        "reverse_neighbors",
                        []
                    )[
                        :self.max_neighbors
                    ],

                    "paths": item.get(
                        "paths",
                        []
                    )[
                        :self.max_paths
                    ]
                }
            )

        return cleaned

    # ========================================================
    # BUILD EVIDENCE
    # ========================================================

    def build_evidence(
        self,
        vector_context,
        graph_context
    ):

        evidence = []

        # ----------------------------------------------------
        # Vector evidence
        # ----------------------------------------------------

        for item in vector_context:

            evidence.append(
                {
                    "source": "MITRE_VECTOR",

                    "name": item.get(
                        "name"
                    ),

                    "mitre_id": item.get(
                        "mitre_id"
                    ),

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

        # ----------------------------------------------------
        # Graph evidence
        # ----------------------------------------------------

        for item in graph_context:

            for entity in item.get(
                "entities",
                []
            ):

                evidence.append(
                    {
                        "source": "NEO4J_GRAPH",

                        "name": entity.get(
                            "name"
                        ),

                        "mitre_id": entity.get(
                            "mitre_id"
                        ),

                        "stix_id": entity.get(
                            "stix_id"
                        ),

                        "description": entity.get(
                            "description"
                        ),

                        "tactics": entity.get(
                            "tactics"
                        ),

                        "neighbors": item.get(
                            "neighbors",
                            []
                        ),

                        "reverse_neighbors": item.get(
                            "reverse_neighbors",
                            []
                        ),

                        "paths": item.get(
                            "paths",
                            []
                        )
                    }
                )

        return evidence

    # ========================================================
    # BUILD LLM PROMPT CONTEXT
    # ========================================================

    def build_prompt_context(
        self,
        query,
        vector_context,
        graph_context
    ):

        lines = []

        lines.append(
            "CYBERSECURITY GRAPHRAG EVIDENCE"
        )

        lines.append(
            f"User Query: {query}"
        )

        lines.append("")

        # ----------------------------------------------------
        # Semantic retrieval
        # ----------------------------------------------------

        lines.append(
            "=== SEMANTIC RETRIEVAL ==="
        )

        for item in vector_context:

            lines.append(
                f"[Rank {item['rank']}] "
                f"{item.get('name')} "
                f"({item.get('mitre_id')})"
            )

            if item.get(
                "type"
            ):

                lines.append(
                    f"Type: "
                    f"{item.get('type')}"
                )

            if item.get(
                "description"
            ):

                lines.append(
                    "Description: "
                    + str(
                        item.get(
                            "description"
                        )
                    )
                )

            lines.append("")

        # ----------------------------------------------------
        # Graph retrieval
        # ----------------------------------------------------

        lines.append(
            "=== KNOWLEDGE GRAPH ==="
        )

        for item in graph_context:

            lines.append(
                f"Entity: "
                f"{item.get('entity')}"
            )

            for entity in item.get(
                "entities",
                []
            ):

                if entity.get(
                    "mitre_id"
                ):

                    lines.append(
                        f"MITRE ID: "
                        f"{entity.get('mitre_id')}"
                    )

                if entity.get(
                    "description"
                ):

                    lines.append(
                        "Description: "
                        + str(
                            entity.get(
                                "description"
                            )
                        )
                    )

                if entity.get(
                    "tactics"
                ):

                    lines.append(
                        f"Tactics: "
                        f"{entity.get('tactics')}"
                    )

            # ------------------------------------------------
            # Relationships
            # ------------------------------------------------

            neighbors = item.get(
                "neighbors",
                []
            )

            if neighbors:

                lines.append(
                    "Relationships:"
                )

                for neighbor in neighbors:

                    lines.append(
                        f"  - {neighbor}"
                    )

            # ------------------------------------------------
            # Reverse relationships
            # ------------------------------------------------

            reverse_neighbors = item.get(
                "reverse_neighbors",
                []
            )

            if reverse_neighbors:

                lines.append(
                    "Reverse Relationships:"
                )

                for neighbor in (
                    reverse_neighbors
                ):

                    lines.append(
                        f"  - {neighbor}"
                    )

            # ------------------------------------------------
            # Multi-hop paths
            # ------------------------------------------------

            paths = item.get(
                "paths",
                []
            )

            if paths:

                lines.append(
                    "Multi-hop Attack Paths:"
                )

                for path in paths:

                    lines.append(
                        f"  - {path}"
                    )

            lines.append("")

        return "\n".join(lines)

    # ========================================================
    # BUILD FINAL CONTEXT
    # ========================================================

    def build(
        self,
        context
    ):

        query = context.get(
            "query"
        )

        vector_results = context.get(
            "vector_results",
            []
        )

        graph_entities = context.get(
            "graph_entities",
            []
        )

        # ----------------------------------------------------
        # Clean vector context
        # ----------------------------------------------------

        vector_context = (
            self.build_vector_context(
                vector_results
            )
        )

        # ----------------------------------------------------
        # Clean graph context
        # ----------------------------------------------------

        graph_context = (
            self.build_graph_context(
                graph_entities
            )
        )

        # ----------------------------------------------------
        # Combined evidence
        # ----------------------------------------------------

        evidence = self.build_evidence(
            vector_context,
            graph_context
        )

        # ----------------------------------------------------
        # LLM-ready text
        # ----------------------------------------------------

        prompt_context = (
            self.build_prompt_context(
                query,
                vector_context,
                graph_context
            )
        )

        # ----------------------------------------------------
        # Final object
        # ----------------------------------------------------

        final_context = {

            "query": query,

            "retrieval_strategy": context.get(
                "retrieval_strategy",
                {}
            ),

            "vector_context": vector_context,

            "graph_context": graph_context,

            "evidence": evidence,

            "llm_context": prompt_context
        }

        return final_context

    # ========================================================
    # SAVE
    # ========================================================

    def save(
        self,
        context,
        output_file=OUTPUT_FILE
    ):

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

        return output_file


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("GRAPHRAG CONTEXT BUILDER TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # Initialize
    # --------------------------------------------------------

    builder = GraphRAGContextBuilder(
        max_vector_results=5,
        max_graph_entities=5,
        max_neighbors=10,
        max_paths=10
    )

    # --------------------------------------------------------
    # Load hybrid context
    # --------------------------------------------------------

    print("\n[1] Loading hybrid context...")

    context = builder.load_context()

    print(
        f"    Query: "
        f"{context.get('query')}"
    )

    # --------------------------------------------------------
    # Build LLM context
    # --------------------------------------------------------

    print(
        "\n[2] Building LLM-ready context..."
    )

    final_context = builder.build(
        context
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print("\n[3] Context statistics")

    print(
        f"    Vector results: "
        f"{len(final_context['vector_context'])}"
    )

    print(
        f"    Graph entities: "
        f"{len(final_context['graph_context'])}"
    )

    print(
        f"    Evidence items: "
        f"{len(final_context['evidence'])}"
    )

    print(
        f"    LLM context characters: "
        f"{len(final_context['llm_context'])}"
    )

    # --------------------------------------------------------
    # Preview
    # --------------------------------------------------------

    print("\n")
    print("-" * 70)
    print("LLM CONTEXT PREVIEW")
    print("-" * 70)

    print(
        final_context["llm_context"][
            :5000
        ]
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    output = builder.save(
        final_context
    )

    print("\n")
    print("=" * 70)
    print("CONTEXT BUILDING COMPLETE")
    print("=" * 70)

    print(
        "\nSaved context to:"
    )

    print(output)