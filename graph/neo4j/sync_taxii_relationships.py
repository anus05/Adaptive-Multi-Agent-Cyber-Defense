import json
import os
from pathlib import Path
from datetime import datetime, UTC

from dotenv import load_dotenv
from neo4j import GraphDatabase


# ============================================================
# PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENV_FILE = PROJECT_ROOT / ".env"

RELATIONSHIP_FILE = (
    PROJECT_ROOT
    / "data"
    / "stix"
    / "taxii_enterprise_relationships.json"
)


# ============================================================
# LOAD ENVIRONMENT
# ============================================================

load_dotenv(ENV_FILE)

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv(
    "NEO4J_DATABASE",
    "neo4j"
)


# ============================================================
# LOAD RELATIONSHIPS
# ============================================================

def load_relationships():

    print()
    print("=" * 60)
    print("LOADING TAXII RELATIONSHIPS")
    print("=" * 60)

    print(
        "File:",
        RELATIONSHIP_FILE
    )

    with open(
        RELATIONSHIP_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        data = json.load(file)

    relationships = data.get(
        "objects",
        []
    )

    print(
        "Relationships loaded:",
        len(relationships)
    )

    return relationships


# ============================================================
# MAP STIX RELATIONSHIP TYPE
# ============================================================

def normalize_relationship_type(
    relationship_type
):

    if not relationship_type:
        return None

    # Neo4j relationship types cannot contain
    # arbitrary STIX characters.
    #
    # ATT&CK relationship types are normally:
    # uses
    # subtechnique-of
    # attributed-to
    # revoked-by
    # etc.

    normalized = (
        relationship_type
        .strip()
        .upper()
        .replace("-", "_")
        .replace(" ", "_")
    )

    return normalized


# ============================================================
# SYNCHRONIZE ONE RELATIONSHIP
# ============================================================

def sync_relationship(
    tx,
    relationship
):

    stix_id = relationship.get(
        "id"
    )

    relationship_type = relationship.get(
        "relationship_type"
    )

    source_ref = relationship.get(
        "source_ref"
    )

    target_ref = relationship.get(
        "target_ref"
    )

    created = relationship.get(
        "created"
    )

    modified = relationship.get(
        "modified"
    )

    # --------------------------------------------------------
    # Validation
    # --------------------------------------------------------

    if not stix_id:
        return "invalid"

    if not relationship_type:
        return "invalid"

    if not source_ref:
        return "invalid"

    if not target_ref:
        return "invalid"

    neo4j_type = normalize_relationship_type(
        relationship_type
    )

    if not neo4j_type:
        return "invalid"

    # --------------------------------------------------------
    # Dynamic relationship type
    # --------------------------------------------------------

    query = f"""
    MATCH (source {{stix_id: $source_ref}})
    MATCH (target {{stix_id: $target_ref}})

    MERGE (source)-[r:{neo4j_type} {{stix_id: $stix_id}}]->(target)

    SET
        r.created = $created,
        r.modified = $modified,
        r.source = "MITRE_TAXII_2.1",
        r.last_synced = $last_synced

    RETURN
        source.stix_id AS source_id,
        target.stix_id AS target_id,
        type(r) AS relationship_type
    """

    result = tx.run(
        query,
        stix_id=stix_id,
        source_ref=source_ref,
        target_ref=target_ref,
        created=created,
        modified=modified,
        last_synced=datetime.now(
            UTC
        ).isoformat()
    )

    record = result.single()

    if record is None:
        return "missing_nodes"

    return "synced"


# ============================================================
# MAIN
# ============================================================

def main():

    print()
    print("#" * 60)
    print("# TAXII → NEO4J RELATIONSHIP SYNCHRONIZATION")
    print("#" * 60)

    # --------------------------------------------------------
    # Load relationships
    # --------------------------------------------------------

    relationships = load_relationships()

    # --------------------------------------------------------
    # Connect to Neo4j
    # --------------------------------------------------------

    print()
    print(
        "Connecting to Neo4j..."
    )

    driver = GraphDatabase.driver(
        NEO4J_URI,
        auth=(
            NEO4J_USERNAME,
            NEO4J_PASSWORD
        )
    )

    driver.verify_connectivity()

    print(
        "✅ Neo4j connection successful"
    )

    # --------------------------------------------------------
    # Counters
    # --------------------------------------------------------

    synced = 0
    missing_nodes = 0
    invalid = 0

    # --------------------------------------------------------
    # Synchronize
    # --------------------------------------------------------

    with driver.session(
        database=NEO4J_DATABASE
    ) as session:

        for relationship in relationships:

            result = session.execute_write(
                sync_relationship,
                relationship
            )

            if result == "synced":

                synced += 1

            elif result == "missing_nodes":

                missing_nodes += 1

            else:

                invalid += 1

    # --------------------------------------------------------
    # Close driver
    # --------------------------------------------------------

    driver.close()

    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("RELATIONSHIP SYNCHRONIZATION SUMMARY")
    print("=" * 60)

    print(
        "Relationships processed:",
        len(relationships)
    )

    print(
        "Relationships synchronized:",
        synced
    )

    print(
        "Missing source/target nodes:",
        missing_nodes
    )

    print(
        "Invalid relationships:",
        invalid
    )

    print()
    print(
        "✅ TAXII relationship synchronization completed"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as e:

        print()
        print(
            "❌ Synchronization failed:"
        )

        print(e)