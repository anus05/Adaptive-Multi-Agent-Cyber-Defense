import json
from pathlib import Path

from graph_retriever import GraphRetriever


# ============================================================
# RETRIEVAL FORMATTER
# ============================================================

class RetrievalFormatter:

    def __init__(self, retriever):

        self.retriever = retriever


    # ========================================================
    # Format entity results
    # ========================================================

    def format_entities(self, results):

        entities = []

        for item in results:

            entities.append({
                "type": (
                    item["labels"][0]
                    if item.get("labels")
                    else "Unknown"
                ),
                "name": item.get("name"),
                "stix_id": item.get("stix_id"),
                "external_id": item.get("external_id")
            })

        return entities


    # ========================================================
    # Format relationships
    # ========================================================

    def format_relationships(self, results):

        relationships = []

        for item in results:

            relationships.append({
                "source": item.get("source"),
                "source_type": (
                    item["source_labels"][0]
                    if item.get("source_labels")
                    else "Unknown"
                ),
                "relationship": item.get("relationship"),
                "target": item.get("target"),
                "target_type": (
                    item["target_labels"][0]
                    if item.get("target_labels")
                    else "Unknown"
                ),
                "target_stix_id": item.get(
                    "target_stix_id"
                ),
                "target_external_id": item.get(
                    "target_external_id"
                )
            })

        return relationships


    # ========================================================
    # Format graph paths
    # ========================================================

    def format_paths(self, results):

        paths = []

        for item in results:

            nodes = item.get("nodes", [])
            relationships = item.get(
                "relationships",
                []
            )

            path_text = ""

            for i, node in enumerate(nodes):

                path_text += node.get(
                    "name",
                    "Unknown"
                )

                if i < len(relationships):

                    path_text += (
                        f" --[{relationships[i]}]--> "
                    )

            paths.append({
                "path": path_text,
                "nodes": nodes,
                "relationships": relationships,
                "hop_count": len(relationships)
            })

        return paths


    # ========================================================
    # Build evidence
    # ========================================================

    def build_evidence(
        self,
        entity_name
    ):

        # Entity
        entity_results = (
            self.retriever.find_entity(
                entity_name
            )
        )

        # Direct relationships
        neighbor_results = (
            self.retriever.get_neighbors(
                entity_name
            )
        )

        # Multi-hop paths
        path_results = (
            self.retriever.get_attack_paths(
                entity_name,
                max_hops=3
            )
        )

        evidence = []

        # ----------------------------------------------------
        # Entity evidence
        # ----------------------------------------------------

        for entity in self.format_entities(
            entity_results
        ):

            evidence.append({
                "evidence_type": "entity",
                "content": entity,
                "source": "Neo4j Cybersecurity Knowledge Graph"
            })


        # ----------------------------------------------------
        # Relationship evidence
        # ----------------------------------------------------

        for relationship in self.format_relationships(
            neighbor_results
        ):

            evidence.append({
                "evidence_type": "relationship",
                "content": relationship,
                "source": "Neo4j Cybersecurity Knowledge Graph"
            })


        # ----------------------------------------------------
        # Path evidence
        # ----------------------------------------------------

        for path in self.format_paths(
            path_results
        ):

            evidence.append({
                "evidence_type": "graph_path",
                "content": path,
                "source": "Neo4j Cybersecurity Knowledge Graph"
            })


        return evidence


    # ========================================================
    # Complete GraphRAG context
    # ========================================================

    def build_context(
        self,
        query
    ):

        entity_results = (
            self.retriever.find_entity(
                query
            )
        )

        neighbor_results = (
            self.retriever.get_neighbors(
                query
            )
        )

        path_results = (
            self.retriever.get_attack_paths(
                query,
                max_hops=3
            )
        )

        context = {

            "query": query,

            "entities": self.format_entities(
                entity_results
            ),

            "relationships": self.format_relationships(
                neighbor_results
            ),

            "paths": self.format_paths(
                path_results
            ),

            "evidence": self.build_evidence(
                query
            )
        }

        return context


# ============================================================
# TEST
# ============================================================

def main():

    print()
    print("#" * 60)
    print("# GRAPHRAG RETRIEVAL CONTEXT TEST")
    print("#" * 60)

    retriever = GraphRetriever()

    try:

        formatter = RetrievalFormatter(
            retriever
        )

        query = "J-magic Campaign"

        context = formatter.build_context(
            query
        )

        print()
        print(
            json.dumps(
                context,
                indent=4,
                ensure_ascii=False
            )
        )

        # ----------------------------------------------------
        # Save result
        # ----------------------------------------------------

        output_dir = (
            Path(__file__).resolve().parents[2]
            / "data"
            / "retrieval"
        )

        output_dir.mkdir(
            parents=True,
            exist_ok=True
        )

        output_file = (
            output_dir
            / "jmagic_context.json"
        )

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                context,
                f,
                indent=4,
                ensure_ascii=False
            )

        print()
        print(
            f"✅ Context saved to:"
        )
        print(
            output_file
        )

    finally:

        retriever.close()

        print()
        print(
            "✅ Retrieval formatting completed"
        )


if __name__ == "__main__":

    main()