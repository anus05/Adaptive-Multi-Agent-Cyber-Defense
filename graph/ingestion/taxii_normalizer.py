import json
from pathlib import Path
from collections import Counter


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "stix"
    / "taxii_enterprise_sample.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "stix"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "taxii_normalized.json"
)


# ============================================================
# OBJECT TYPES WE CARE ABOUT
# ============================================================

SUPPORTED_TYPES = {
    "attack-pattern",
    "intrusion-set",
    "malware",
    "tool",
    "campaign",
    "course-of-action",
    "relationship",
}


# ============================================================
# NORMALIZE STIX OBJECT
# ============================================================

def normalize_object(obj):

    object_type = obj.get("type")

    normalized = {
        "stix_id": obj.get("id"),
        "type": object_type,
        "name": obj.get("name"),
        "description": obj.get("description"),
        "created": obj.get("created"),
        "modified": obj.get("modified"),
        "revoked": obj.get("revoked", False),
        "source": "MITRE_TAXII_2.1",
    }

    # --------------------------------------------------------
    # ATT&CK external ID
    # --------------------------------------------------------

    external_id = None

    for reference in obj.get(
        "external_references",
        []
    ):

        if (
            reference.get("source_name")
            == "mitre-attack"
        ):

            external_id = reference.get(
                "external_id"
            )

            break

    normalized["external_id"] = external_id

    # --------------------------------------------------------
    # ATT&CK kill chain phases
    # --------------------------------------------------------

    normalized["tactics"] = [
        phase.get("phase_name")
        for phase in obj.get(
            "kill_chain_phases",
            []
        )
        if phase.get("phase_name")
    ]

    # --------------------------------------------------------
    # STIX relationship
    # --------------------------------------------------------

    if object_type == "relationship":

        normalized["relationship_type"] = obj.get(
            "relationship_type"
        )

        normalized["source_ref"] = obj.get(
            "source_ref"
        )

        normalized["target_ref"] = obj.get(
            "target_ref"
        )

    return normalized


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("#" * 60)
    print("# TAXII STIX NORMALIZATION")
    print("#" * 60)

    # --------------------------------------------------------
    # Load TAXII data
    # --------------------------------------------------------

    print()
    print("Loading:")
    print(INPUT_FILE)

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    objects = data.get(
        "objects",
        []
    )

    print(
        "Objects loaded:",
        len(objects)
    )

    # --------------------------------------------------------
    # Normalize
    # --------------------------------------------------------

    normalized_objects = []

    skipped = 0

    for obj in objects:

        object_type = obj.get(
            "type"
        )

        if object_type not in SUPPORTED_TYPES:

            skipped += 1
            continue

        normalized = normalize_object(
            obj
        )

        normalized_objects.append(
            normalized
        )

    # --------------------------------------------------------
    # Count types
    # --------------------------------------------------------

    counts = Counter(
        obj.get("type")
        for obj in normalized_objects
    )

    print()
    print("Normalized object types:")

    for object_type, count in sorted(
        counts.items()
    ):

        print(
            f"{object_type:25} {count}"
        )

    print()
    print(
        "Skipped objects:",
        skipped
    )

    # --------------------------------------------------------
    # Output
    # --------------------------------------------------------

    output = {
        "source": "MITRE TAXII 2.1",
        "collection_id": data.get(
            "collection_id"
        ),
        "object_count": len(
            normalized_objects
        ),
        "objects": normalized_objects,
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("Saved to:")
    print(OUTPUT_FILE)

    print()
    print(
        "✅ TAXII normalization completed"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()