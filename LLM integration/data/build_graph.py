import json
from pathlib import Path
from collections import Counter

import networkx as nx


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATA_FILE = BASE_DIR / "processed" / "train_clean.jsonl"

OUTPUT_DIR = BASE_DIR / "processed"

GRAPH_FILE = OUTPUT_DIR / "cyber_threat_graph.gexf"


# ---------------------------------------------------------
# Load records
# ---------------------------------------------------------

def load_records(file_path):

    records = []

    with open(file_path, "r", encoding="utf-8") as f:

        for line in f:

            line = line.strip()

            if not line:
                continue

            records.append(json.loads(line))

    return records


# ---------------------------------------------------------
# Build graph
# ---------------------------------------------------------

def build_graph(records):

    graph = nx.MultiDiGraph()

    entity_type_counter = Counter()
    relation_counter = Counter()

    for record in records:

        entities = record.get("entities", [])
        relations = record.get("relations", [])

        # -------------------------------------------------
        # Add entity nodes
        # -------------------------------------------------

        for entity in entities:

            entity_id = entity.get("id")

            if entity_id is None:
                continue

            entity_label = entity.get(
                "label",
                "UNKNOWN"
            )

            entity_text = entity.get(
                "text",
                ""
            )

            graph.add_node(
                str(entity_id),
                entity_type=entity_label,
                name=entity_text,
                record_id=record.get("id")
            )

            entity_type_counter[entity_label] += 1

        # -------------------------------------------------
        # Add relationship edges
        # -------------------------------------------------

        for relation in relations:

            from_id = relation.get("from_id")
            to_id = relation.get("to_id")
            relation_type = relation.get(
                "type",
                "UNKNOWN"
            )

            if from_id is None or to_id is None:
                continue

            # Only add if both nodes exist
            if (
                str(from_id) in graph.nodes
                and
                str(to_id) in graph.nodes
            ):

                graph.add_edge(
                    str(from_id),
                    str(to_id),
                    relation=relation_type,
                    record_id=record.get("id")
                )

                relation_counter[relation_type] += 1

    return graph, entity_type_counter, relation_counter


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    print("=" * 60)
    print("CYBERSECURITY KNOWLEDGE GRAPH")
    print("=" * 60)

    records = load_records(DATA_FILE)

    print(f"Records loaded: {len(records)}")

    graph, entity_counts, relation_counts = build_graph(
        records
    )

    print("\nGRAPH STATISTICS")
    print("-" * 40)

    print(f"Nodes: {graph.number_of_nodes()}")
    print(f"Edges: {graph.number_of_edges()}")

    print("\nENTITY TYPES")
    print("-" * 40)

    for entity_type, count in entity_counts.most_common():

        print(
            f"{entity_type}: {count}"
        )

    print("\nRELATION TYPES")
    print("-" * 40)

    for relation_type, count in relation_counts.most_common():

        print(
            f"{relation_type}: {count}"
        )

    # -----------------------------------------------------
    # Save graph
    # -----------------------------------------------------

    nx.write_gexf(
        graph,
        GRAPH_FILE
    )

    print("\nGraph saved to:")
    print(GRAPH_FILE)

    print("\n" + "=" * 60)
    print("GRAPH BUILDING COMPLETE")
    print("=" * 60)