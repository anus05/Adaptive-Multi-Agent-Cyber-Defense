import json
import requests
from pathlib import Path
from collections import Counter


# MITRE ATT&CK Enterprise STIX dataset
URL = (
    "https://raw.githubusercontent.com/mitre-attack/"
    "attack-stix-data/master/enterprise-attack/enterprise-attack.json"
)

# Output directory
OUTPUT_DIR = Path("data/mitre")
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def download_mitre_data():
    print("Downloading MITRE ATT&CK data...")

    response = requests.get(URL, timeout=60)
    response.raise_for_status()

    print("Download successful.")
    return response.json()


def extract_objects(data):
    objects = data["objects"]

    # Objects we currently need for our Knowledge Graph
    required_types = {
        "attack-pattern",
        "intrusion-set",
        "malware",
        "tool",
        "campaign",
        "relationship",
    }

    extracted = {
        object_type: []
        for object_type in required_types
    }

    for obj in objects:
        object_type = obj.get("type")

        if object_type in required_types:
            extracted[object_type].append(obj)

    return extracted


def normalize_attack_pattern(obj):
    """
    Convert MITRE attack-pattern STIX object
    into a simpler representation for our graph.
    """

    external_id = None

    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            external_id = ref.get("external_id")
            break

    tactics = []

    for phase in obj.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name"))

    return {
        "stix_id": obj.get("id"),
        "mitre_id": external_id,
        "name": obj.get("name"),
        "description": obj.get("description"),
        "tactics": tactics,
    }


def normalize_entity(obj):
    """
    Normalize Threat Actors, Malware, Tools and Campaigns.
    """

    return {
        "stix_id": obj.get("id"),
        "name": obj.get("name"),
        "description": obj.get("description"),
    }


def normalize_relationship(obj):
    """
    Extract graph relationships.
    """

    return {
        "stix_id": obj.get("id"),
        "relationship_type": obj.get("relationship_type"),
        "source_ref": obj.get("source_ref"),
        "target_ref": obj.get("target_ref"),
        "description": obj.get("description"),
    }


def main():

    # -----------------------------------------
    # 1. Download
    # -----------------------------------------

    data = download_mitre_data()

    objects = data["objects"]

    print()
    print("Total STIX objects:", len(objects))

    # -----------------------------------------
    # 2. Count object types
    # -----------------------------------------

    type_counts = Counter(
        obj.get("type")
        for obj in objects
    )

    print("\nSTIX object types:")
    print("-" * 40)

    for object_type, count in type_counts.most_common():
        print(f"{object_type:<30} {count}")

    # -----------------------------------------
    # 3. Extract useful objects
    # -----------------------------------------

    extracted = extract_objects(data)

    print("\nSelected objects:")
    print("-" * 40)

    for object_type, items in extracted.items():
        print(f"{object_type:<30} {len(items)}")

    # -----------------------------------------
    # 4. Normalize the data
    # -----------------------------------------

    normalized = {

        "attack_patterns": [
            normalize_attack_pattern(obj)
            for obj in extracted["attack-pattern"]
        ],

        "threat_actors": [
            normalize_entity(obj)
            for obj in extracted["intrusion-set"]
        ],

        "malware": [
            normalize_entity(obj)
            for obj in extracted["malware"]
        ],

        "tools": [
            normalize_entity(obj)
            for obj in extracted["tool"]
        ],

        "campaigns": [
            normalize_entity(obj)
            for obj in extracted["campaign"]
        ],

        "relationships": [
            normalize_relationship(obj)
            for obj in extracted["relationship"]
        ],
    }

    # -----------------------------------------
    # 5. Save normalized data
    # -----------------------------------------

    output_file = OUTPUT_DIR / "mitre_normalized.json"

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(
            normalized,
            f,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("=" * 50)
    print("MITRE normalization completed.")
    print(f"Saved to: {output_file}")
    print("=" * 50)

    # -----------------------------------------
    # 6. Display examples
    # -----------------------------------------

    print("\nExample Technique:")

    if normalized["attack_patterns"]:
        technique = normalized["attack_patterns"][0]

        print("MITRE ID :", technique["mitre_id"])
        print("Name     :", technique["name"])
        print("Tactics  :", technique["tactics"])

    print("\nExample Threat Actor:")

    if normalized["threat_actors"]:
        actor = normalized["threat_actors"][0]

        print("Name:", actor["name"])

    print("\nExample Relationship:")

    if normalized["relationships"]:
        relationship = normalized["relationships"][0]

        print("Type   :", relationship["relationship_type"])
        print("Source :", relationship["source_ref"])
        print("Target :", relationship["target_ref"])


if __name__ == "__main__":
    main()