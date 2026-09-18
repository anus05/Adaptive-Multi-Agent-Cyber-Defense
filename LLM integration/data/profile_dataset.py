import json
from collections import Counter


def load_jsonl(file_path):
    records = []

    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line:
                records.append(json.loads(line))

    return records


def analyze_dataset(file_path):
    records = load_jsonl(file_path)

    print("\n" + "=" * 60)
    print(f"DATASET: {file_path}")
    print("=" * 60)

    print(f"Total records: {len(records)}")

    # --------------------------------------------------
    # Basic statistics
    # --------------------------------------------------

    records_with_entities = 0
    records_without_entities = 0

    records_with_relations = 0
    records_without_relations = 0

    entity_counter = Counter()
    relation_counter = Counter()

    total_entities = 0
    total_relations = 0

    # --------------------------------------------------
    # Analyze each record
    # --------------------------------------------------

    for record in records:

        entities = record.get("entities", [])
        relations = record.get("relations", [])

        # Entity statistics
        if entities:
            records_with_entities += 1
        else:
            records_without_entities += 1

        # Relation statistics
        if relations:
            records_with_relations += 1
        else:
            records_without_relations += 1

        # Count entities
        for entity in entities:
            label = entity.get("label", "UNKNOWN")
            entity_counter[label] += 1
            total_entities += 1

        # Count relations
        for relation in relations:

            # Print unknown structure later if necessary
            if isinstance(relation, dict):

                relation_type = (
                    relation.get("label")
                    or relation.get("type")
                    or relation.get("relation")
                    or "UNKNOWN"
                )

            else:
                relation_type = "UNKNOWN"

            relation_counter[relation_type] += 1
            total_relations += 1

    # --------------------------------------------------
    # Print statistics
    # --------------------------------------------------

    print("\nENTITY STATISTICS")
    print("-" * 40)

    print(f"Total entities: {total_entities}")
    print(f"Records with entities: {records_with_entities}")
    print(f"Records without entities: {records_without_entities}")

    print("\nEntity types:")

    for entity_type, count in entity_counter.most_common():
        print(f"  {entity_type}: {count}")

    # --------------------------------------------------

    print("\nRELATION STATISTICS")
    print("-" * 40)

    print(f"Total relations: {total_relations}")
    print(f"Records with relations: {records_with_relations}")
    print(f"Records without relations: {records_without_relations}")

    print("\nRelation types:")

    for relation_type, count in relation_counter.most_common():
        print(f"  {relation_type}: {count}")

    # --------------------------------------------------
    # Show records containing relations
    # --------------------------------------------------

    print("\nEXAMPLE RECORDS WITH RELATIONS")
    print("-" * 40)

    shown = 0

    for record in records:

        relations = record.get("relations", [])

        if relations:

            print("\nRecord ID:", record.get("id"))
            print("Text:", record.get("text"))
            print("Entities:", record.get("entities"))
            print("Relations:", relations)

            shown += 1

            if shown >= 3:
                break


if __name__ == "__main__":

    analyze_dataset("data/raw/train.jsonl")

    analyze_dataset("data/raw/validation.jsonl")

    analyze_dataset("data/raw/test.jsonl")