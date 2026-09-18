import json
import re
from pathlib import Path
from collections import Counter

from langdetect import detect, LangDetectException


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

RAW_DIR = BASE_DIR / "raw"
PROCESSED_DIR = BASE_DIR / "processed"

PROCESSED_DIR.mkdir(exist_ok=True)


# ---------------------------------------------------------
# Load JSONL
# ---------------------------------------------------------

def load_jsonl(file_path):
    records = []

    with open(file_path, "r", encoding="utf-8") as f:

        for line_number, line in enumerate(f, start=1):

            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
                records.append(record)

            except json.JSONDecodeError as e:

                print(
                    f"Warning: invalid JSON at line {line_number}: {e}"
                )

    return records


# ---------------------------------------------------------
# Clean text
# ---------------------------------------------------------

def clean_text(text):

    if not isinstance(text, str):
        return ""

    # Remove excessive whitespace
    text = re.sub(r"\s+", " ", text)

    # Remove leading/trailing spaces
    text = text.strip()

    return text


# ---------------------------------------------------------
# Detect language
# ---------------------------------------------------------

def detect_language(text):

    if not text or len(text.strip()) < 10:
        return "unknown"

    try:
        return detect(text)

    except LangDetectException:
        return "unknown"


# ---------------------------------------------------------
# Extract entity surface text
# ---------------------------------------------------------

def extract_entity_text(text, entity):

    start = entity.get("start_offset")
    end = entity.get("end_offset")

    if start is None or end is None:
        return None

    if not isinstance(start, int) or not isinstance(end, int):
        return None

    if start < 0 or end > len(text) or start >= end:
        return None

    return text[start:end]


# ---------------------------------------------------------
# Process one record
# ---------------------------------------------------------

def process_record(record):

    original_text = record.get("text", "")

    text = clean_text(original_text)

    entities = []
    invalid_entities = 0

    # -----------------------------------------------------
    # Process entities
    # -----------------------------------------------------

    for entity in record.get("entities", []):

        entity_text = extract_entity_text(
            original_text,
            entity
        )

        if entity_text is None:
            invalid_entities += 1
            continue

        entities.append({
            "id": entity.get("id"),
            "label": entity.get("label", "UNKNOWN"),
            "text": entity_text.strip(),
            "start_offset": entity.get("start_offset"),
            "end_offset": entity.get("end_offset")
        })

    # -----------------------------------------------------
    # Process relations
    # -----------------------------------------------------

    relations = []

    entity_ids = {
        entity.get("id")
        for entity in record.get("entities", [])
    }

    for relation in record.get("relations", []):

        from_id = relation.get("from_id")
        to_id = relation.get("to_id")

        relations.append({
            "id": relation.get("id"),
            "from_id": from_id,
            "to_id": to_id,
            "type": relation.get("type", "UNKNOWN"),
            "valid_source": from_id in entity_ids,
            "valid_target": to_id in entity_ids
        })

    # -----------------------------------------------------
    # Language
    # -----------------------------------------------------

    language = detect_language(text)

    # -----------------------------------------------------
    # Final normalized record
    # -----------------------------------------------------

    return {
        "id": record.get("id"),
        "text": text,
        "language": language,
        "entities": entities,
        "relations": relations,
        "comments": record.get("Comments", []),
        "entity_count": len(entities),
        "relation_count": len(relations),
        "invalid_entities": invalid_entities
    }


# ---------------------------------------------------------
# Process dataset
# ---------------------------------------------------------

def process_dataset(input_file, output_file):

    print("\n" + "=" * 60)
    print(f"Processing: {input_file.name}")
    print("=" * 60)

    records = load_jsonl(input_file)

    processed_records = []

    language_counter = Counter()

    total_entities = 0
    total_relations = 0
    invalid_entities = 0

    empty_text_records = 0

    for record in records:

        processed = process_record(record)

        if not processed["text"]:
            empty_text_records += 1
            continue

        processed_records.append(processed)

        language_counter[processed["language"]] += 1

        total_entities += processed["entity_count"]
        total_relations += processed["relation_count"]
        invalid_entities += processed["invalid_entities"]

    # -----------------------------------------------------
    # Save
    # -----------------------------------------------------

    with open(
        output_file,
        "w",
        encoding="utf-8"
    ) as f:

        for record in processed_records:

            f.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )

    # -----------------------------------------------------
    # Print summary
    # -----------------------------------------------------

    print(f"Original records: {len(records)}")
    print(f"Processed records: {len(processed_records)}")
    print(f"Empty text records: {empty_text_records}")

    print(f"Total entities: {total_entities}")
    print(f"Total relations: {total_relations}")

    print(f"Invalid entities: {invalid_entities}")

    print("\nLanguage distribution:")

    for language, count in language_counter.most_common():

        print(f"  {language}: {count}")

    print(f"\nSaved to: {output_file}")


# ---------------------------------------------------------
# Main
# ---------------------------------------------------------

if __name__ == "__main__":

    process_dataset(
        RAW_DIR / "train.jsonl",
        PROCESSED_DIR / "train_clean.jsonl"
    )

    process_dataset(
        RAW_DIR / "validation.jsonl",
        PROCESSED_DIR / "validation_clean.jsonl"
    )

    process_dataset(
        RAW_DIR / "test.jsonl",
        PROCESSED_DIR / "test_clean.jsonl"
    )

    print("\n" + "=" * 60)
    print("PREPROCESSING COMPLETE")
    print("=" * 60)