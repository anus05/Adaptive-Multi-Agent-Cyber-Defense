import json
from pathlib import Path
from datetime import datetime, UTC

from neo4j import GraphDatabase
from dotenv import load_dotenv
import os


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

URI = os.getenv("NEO4J_URI")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")
DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


# ============================================================
# TAXII FILE
# ============================================================

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "stix"
    / "taxii_normalized.json"
)


# ============================================================
# LOAD TAXII DATA
# ============================================================

def load_taxii_data():

    with open(
        INPUT_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        return json.load(file)


# ============================================================
# CREATE / UPDATE NODE
# ============================================================

def sync_entity(tx, obj):

    object_type = obj.get("type")

    stix_id = obj.get("stix_id")

    name = obj.get("name")

    description = obj.get("description")

    modified = obj.get("modified")

    external_id = obj.get("external_id")

    revoked = obj.get("revoked", False)

    # --------------------------------------------------------
    # Map STIX types to Neo4j labels
    # --------------------------------------------------------

    label_map = {
        "attack-pattern": "Technique",
        "intrusion-set": "ThreatActor",
        "malware": "Malware",
        "tool": "Tool",
        "campaign": "Campaign",
        "course-of-action": "CourseOfAction",
    }

    label = label_map.get(object_type)

    if not label:
        return "skipped"

    # --------------------------------------------------------
    # Dynamic label
    # --------------------------------------------------------

    query = f"""
    MERGE (n:{label} {{stix_id: $stix_id}})

    SET
        n.name = $name,
        n.description = $description,
        n.modified = $modified,
        n.external_id = $external_id,
        n.revoked = $revoked,
        n.source = "MITRE_TAXII_2.1",
        n.last_synced = $last_synced

    RETURN n.stix_id AS stix_id
    """

    tx.run(
        query,
        stix_id=stix_id,
        name=name,
        description=description,
        modified=modified,
        external_id=external_id,
        revoked=revoked,
        last_synced=datetime.now(UTC).isoformat()
    )

    return "synced"


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("#" * 60)
    print("# TAXII → NEO4J SYNCHRONIZATION")
    print("#" * 60)

    # --------------------------------------------------------
    # Load data
    # --------------------------------------------------------

    data = load_taxii_data()

    objects = data.get(
        "objects",
        []
    )

    print()
    print(
        "Objects loaded:",
        len(objects)
    )

    # --------------------------------------------------------
    # Connect Neo4j
    # --------------------------------------------------------

    print()
    print("Connecting to Neo4j...")

    driver = GraphDatabase.driver(
        URI,
        auth=(
            USERNAME,
            PASSWORD
        )
    )

    driver.verify_connectivity()

    print(
        "✅ Neo4j connection successful"
    )

    # --------------------------------------------------------
    # Sync
    # --------------------------------------------------------

    synced = 0
    skipped = 0

    with driver.session(
        database=DATABASE
    ) as session:

        for obj in objects:

            result = session.execute_write(
                sync_entity,
                obj
            )

            if result == "synced":
                synced += 1
            else:
                skipped += 1

    driver.close()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("SYNCHRONIZATION SUMMARY")
    print("=" * 60)

    print(
        "Objects processed:",
        len(objects)
    )

    print(
        "Objects synchronized:",
        synced
    )

    print(
        "Objects skipped:",
        skipped
    )

    print()
    print(
        "✅ TAXII → Neo4j synchronization completed"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()