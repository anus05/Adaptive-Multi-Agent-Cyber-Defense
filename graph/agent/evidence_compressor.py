import json
import sys
from pathlib import Path


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# PATHS
# ============================================================

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "retrieval"
    / "graph_agent_result.json"
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
    / "compressed_context.json"
)


# ============================================================
# EVIDENCE COMPRESSOR
# ============================================================

class EvidenceCompressor:

    def __init__(
        self,
        max_description_chars=1200,
        max_relationships=20,
        max_attack_paths=10
    ):

        self.max_description_chars = (
            max_description_chars
        )

        self.max_relationships = (
            max_relationships
        )

        self.max_attack_paths = (
            max_attack_paths
        )

    # ========================================================
    # LOAD
    # ========================================================

    def load(self):

        with open(
            INPUT_FILE,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)

    # ========================================================
    # TRUNCATE TEXT
    # ========================================================

    def truncate(
        self,
        text,
        max_chars
    ):

        if not text:
            return ""

        text = str(text)

        if len(text) <= max_chars:
            return text

        return (
            text[:max_chars]
            + "... [truncated]"
        )

    # ========================================================
    # TECHNIQUES
    # ========================================================

    def compress_techniques(
        self,
        techniques
    ):

        compressed = []

        for technique in techniques:

            compressed.append(
                {
                    "name": technique.get(
                        "name"
                    ),

                    "mitre_id": technique.get(
                        "mitre_id"
                    ),

                    "type": technique.get(
                        "type"
                    ),

                    "description": self.truncate(
                        technique.get(
                            "description"
                        ),
                        self.max_description_chars
                    ),

                    "retrieval_rank": technique.get(
                        "retrieval_rank"
                    ),

                    "distance": technique.get(
                        "distance"
                    )
                }
            )

        return compressed

    # ========================================================
    # RELATIONSHIPS
    # ========================================================

    def compress_relationships(
        self,
        relationships
    ):

        compressed = []

        seen = set()

        for relationship in relationships:

            source = relationship.get(
                "source"
            )

            relation = relationship.get(
                "relationship"
            )

            direction = relationship.get(
                "direction"
            )

            # -----------------------------------------------
            # Build unique relationship key
            # -----------------------------------------------

            key = (
                str(source),
                str(relation),
                str(direction)
            )

            if key in seen:
                continue

            seen.add(key)

            # -----------------------------------------------
            # Extract actual graph relationship
            # -----------------------------------------------

            relation_data = relationship.get(
                "relationship"
            )

            if isinstance(
                relation_data,
                dict
            ):

                compressed.append(
                    {
                        "source": relation_data.get(
                            "source"
                        ),

                        "relationship": relation_data.get(
                            "relationship"
                        ),

                        "target": relation_data.get(
                            "target"
                        ),

                        "direction": direction
                    }
                )

            else:

                compressed.append(
                    {
                        "source": source,

                        "relationship": relation_data,

                        "direction": direction
                    }
                )

            if len(compressed) >= (
                self.max_relationships
            ):
                break

        return compressed

    # ========================================================
    # ATTACK PATHS
    # ========================================================

    def compress_paths(
        self,
        attack_paths
    ):

        compressed = []

        for item in attack_paths[
            :self.max_attack_paths
        ]:

            path = item.get(
                "path"
            )

            start_entity = item.get(
                "start_entity"
            )

            # -----------------------------------------------
            # Neo4j path object
            # -----------------------------------------------

            if isinstance(
                path,
                dict
            ):

                nodes = path.get(
                    "nodes",
                    []
                )

                relationships = path.get(
                    "relationships",
                    []
                )

                node_names = []

                for node in nodes:

                    if isinstance(
                        node,
                        dict
                    ):

                        name = node.get(
                            "name"
                        )

                        if name:
                            node_names.append(
                                name
                            )

                compressed.append(
                    {
                        "start_entity": (
                            start_entity
                        ),

                        "nodes": node_names,

                        "relationships": (
                            relationships
                        )
                    }
                )

            else:

                compressed.append(
                    {
                        "start_entity": (
                            start_entity
                        ),

                        "path": str(
                            path
                        )
                    }
                )

        return compressed

    # ========================================================
    # EVIDENCE SUMMARY
    # ========================================================

    def build_evidence_summary(
        self,
        techniques,
        relationships,
        attack_paths
    ):

        summary = []

        # ----------------------------------------------------
        # Technique evidence
        # ----------------------------------------------------

        for technique in techniques:

            summary.append(
                {
                    "evidence_type": (
                        "MITRE_TECHNIQUE"
                    ),

                    "name": technique.get(
                        "name"
                    ),

                    "mitre_id": technique.get(
                        "mitre_id"
                    ),

                    "description": technique.get(
                        "description"
                    )
                }
            )

        # ----------------------------------------------------
        # Relationship evidence
        # ----------------------------------------------------

        for relationship in relationships:

            summary.append(
                {
                    "evidence_type": (
                        "GRAPH_RELATIONSHIP"
                    ),

                    "source": relationship.get(
                        "source"
                    ),

                    "relationship": relationship.get(
                        "relationship"
                    ),

                    "target": relationship.get(
                        "target"
                    ),

                    "direction": relationship.get(
                        "direction"
                    )
                }
            )

        # ----------------------------------------------------
        # Path evidence
        # ----------------------------------------------------

        for path in attack_paths:

            summary.append(
                {
                    "evidence_type": (
                        "MULTI_HOP_PATH"
                    ),

                    "start_entity": path.get(
                        "start_entity"
                    ),

                    "nodes": path.get(
                        "nodes",
                        []
                    ),

                    "relationships": path.get(
                        "relationships",
                        []
                    )
                }
            )

        return summary

    # ========================================================
    # BUILD COMPACT LLM CONTEXT
    # ========================================================

    def build_llm_context(
        self,
        query,
        techniques,
        relationships,
        attack_paths
    ):

        lines = []

        lines.append(
            "CYBERSECURITY GRAPHRAG EVIDENCE"
        )

        lines.append(
            f"Query: {query}"
        )

        lines.append("")

        # ----------------------------------------------------
        # Techniques
        # ----------------------------------------------------

        lines.append(
            "=== MITRE ATT&CK TECHNIQUES ==="
        )

        for technique in techniques:

            lines.append(
                f"- "
                f"{technique.get('name')} "
                f"("
                f"{technique.get('mitre_id')}"
                f")"
            )

            description = technique.get(
                "description"
            )

            if description:

                lines.append(
                    f"  {description}"
                )

        lines.append("")

        # ----------------------------------------------------
        # Relationships
        # ----------------------------------------------------

        lines.append(
            "=== GRAPH RELATIONSHIPS ==="
        )

        for relationship in relationships:

            source = relationship.get(
                "source"
            )

            relation = relationship.get(
                "relationship"
            )

            target = relationship.get(
                "target"
            )

            if target:

                lines.append(
                    f"- {source} "
                    f"--[{relation}]--> "
                    f"{target}"
                )

            else:

                lines.append(
                    f"- {source} "
                    f"--[{relation}]"
                )

        lines.append("")

        # ----------------------------------------------------
        # Paths
        # ----------------------------------------------------

        lines.append(
            "=== MULTI-HOP GRAPH PATHS ==="
        )

        for path in attack_paths:

            nodes = path.get(
                "nodes",
                []
            )

            relationships = path.get(
                "relationships",
                []
            )

            if nodes:

                path_string = (
                    " -> ".join(
                        str(node)
                        for node in nodes
                    )
                )

                lines.append(
                    f"- {path_string}"
                )

            elif path.get(
                "path"
            ):

                lines.append(
                    f"- "
                    f"{path.get('path')}"
                )

        lines.append("")

        # ----------------------------------------------------
        # Grounding rules
        # ----------------------------------------------------

        lines.append(
            "=== GROUNDING RULES ==="
        )

        lines.append(
            "- Use retrieved evidence as the "
            "primary basis for analysis."
        )

        lines.append(
            "- Do not invent unsupported "
            "relationships or techniques."
        )

        lines.append(
            "- Distinguish retrieved facts "
            "from analytical inference."
        )

        lines.append(
            "- Cite MITRE ATT&CK IDs when "
            "available."
        )

        return "\n".join(lines)

    # ========================================================
    # BUILD
    # ========================================================

    def build(
        self,
        data
    ):

        query = data.get(
            "query",
            ""
        )

        techniques = (
            data.get(
                "techniques",
                []
            )
        )

        relationships = (
            data.get(
                "relationships",
                []
            )
        )

        attack_paths = (
            data.get(
                "attack_paths",
                []
            )
        )

        # ----------------------------------------------------
        # Compress
        # ----------------------------------------------------

        compressed_techniques = (
            self.compress_techniques(
                techniques
            )
        )

        compressed_relationships = (
            self.compress_relationships(
                relationships
            )
        )

        compressed_paths = (
            self.compress_paths(
                attack_paths
            )
        )

        evidence_summary = (
            self.build_evidence_summary(
                compressed_techniques,
                compressed_relationships,
                compressed_paths
            )
        )

        llm_context = (
            self.build_llm_context(
                query,
                compressed_techniques,
                compressed_relationships,
                compressed_paths
            )
        )

        # ----------------------------------------------------
        # Final context
        # ----------------------------------------------------

        return {

            "query": query,

            "source_agent": (
                "GraphAgent"
            ),

            "retrieval_strategy": (
                data.get(
                    "retrieval",
                    {}
                )
            ),

            "techniques": (
                compressed_techniques
            ),

            "relationships": (
                compressed_relationships
            ),

            "attack_paths": (
                compressed_paths
            ),

            "evidence": (
                evidence_summary
            ),

            "llm_context": llm_context,

            "statistics": {

                "original_techniques": (
                    len(techniques)
                ),

                "compressed_techniques": (
                    len(compressed_techniques)
                ),

                "original_relationships": (
                    len(relationships)
                ),

                "compressed_relationships": (
                    len(compressed_relationships)
                ),

                "original_attack_paths": (
                    len(attack_paths)
                ),

                "compressed_attack_paths": (
                    len(compressed_paths)
                ),

                "llm_context_characters": (
                    len(llm_context)
                )
            }
        }

    # ========================================================
    # SAVE
    # ========================================================

    def save(
        self,
        data
    ):

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                data,
                f,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        return OUTPUT_FILE


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("GRAPHRAG EVIDENCE COMPRESSION TEST")
    print("=" * 70)

    compressor = EvidenceCompressor(
        max_description_chars=1200,
        max_relationships=20,
        max_attack_paths=10
    )

    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    print(
        "\n[1] Loading Graph Agent result..."
    )

    data = compressor.load()

    print(
        f"    Query: "
        f"{data.get('query')}"
    )

    # --------------------------------------------------------
    # Original size
    # --------------------------------------------------------

    original_context = data.get(
        "llm_context",
        ""
    )

    print(
        f"    Original context: "
        f"{len(original_context)} characters"
    )

    # --------------------------------------------------------
    # Compress
    # --------------------------------------------------------

    print(
        "\n[2] Compressing evidence..."
    )

    compressed = compressor.build(
        data
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    stats = compressed[
        "statistics"
    ]

    print(
        "\n[3] Compression statistics"
    )

    print(
        f"    Techniques: "
        f"{stats['original_techniques']} "
        f"-> "
        f"{stats['compressed_techniques']}"
    )

    print(
        f"    Relationships: "
        f"{stats['original_relationships']} "
        f"-> "
        f"{stats['compressed_relationships']}"
    )

    print(
        f"    Attack paths: "
        f"{stats['original_attack_paths']} "
        f"-> "
        f"{stats['compressed_attack_paths']}"
    )

    print(
        f"    Compressed context: "
        f"{stats['llm_context_characters']} "
        f"characters"
    )

    # --------------------------------------------------------
    # Preview
    # --------------------------------------------------------

    print("\n")
    print("-" * 70)
    print("COMPRESSED LLM CONTEXT")
    print("-" * 70)

    print(
        compressed["llm_context"]
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    output = compressor.save(
        compressed
    )

    print("\n")
    print("=" * 70)
    print("EVIDENCE COMPRESSION COMPLETE")
    print("=" * 70)

    print(
        f"\nSaved compressed context to:"
    )

    print(output)