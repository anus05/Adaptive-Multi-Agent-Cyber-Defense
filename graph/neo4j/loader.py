import json
import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase


# ============================================================
# Load environment variables
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")


NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


# ============================================================
# MITRE data location
# ============================================================

MITRE_FILE = PROJECT_ROOT / "data" / "mitre" / "mitre_normalized.json"


# ============================================================
# Neo4j connection
# ============================================================

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)


# ============================================================
# Load JSON
# ============================================================

def load_mitre_data():

    print("Loading MITRE normalized data...")

    with open(MITRE_FILE, "r", encoding="utf-8") as file:
        data = json.load(file)

    print("MITRE data loaded successfully.")

    return data


# ============================================================
# Create constraints
# ============================================================

def create_constraints(tx):

    queries = [

        """
        CREATE CONSTRAINT threat_actor_stix_id IF NOT EXISTS
        FOR (n:ThreatActor)
        REQUIRE n.stix_id IS UNIQUE
        """,

        """
        CREATE CONSTRAINT technique_stix_id IF NOT EXISTS
        FOR (n:Technique)
        REQUIRE n.stix_id IS UNIQUE
        """,

        """
        CREATE CONSTRAINT malware_stix_id IF NOT EXISTS
        FOR (n:Malware)
        REQUIRE n.stix_id IS UNIQUE
        """,

        """
        CREATE CONSTRAINT tool_stix_id IF NOT EXISTS
        FOR (n:Tool)
        REQUIRE n.stix_id IS UNIQUE
        """,

        """
        CREATE CONSTRAINT campaign_stix_id IF NOT EXISTS
        FOR (n:Campaign)
        REQUIRE n.stix_id IS UNIQUE
        """,

        """
        CREATE CONSTRAINT tactic_name IF NOT EXISTS
        FOR (n:Tactic)
        REQUIRE n.name IS UNIQUE
        """
    ]

    for query in queries:
        tx.run(query)


# ============================================================
# Import Threat Actors
# ============================================================

def import_threat_actors(tx, actors):

    query = """
    UNWIND $actors AS actor

    MERGE (a:ThreatActor {
        stix_id: actor.stix_id
    })

    SET
        a.name = actor.name,
        a.description = actor.description
    """

    tx.run(query, actors=actors)


# ============================================================
# Import Techniques
# ============================================================

def import_techniques(tx, techniques):

    query = """
    UNWIND $techniques AS technique

    MERGE (t:Technique {
        stix_id: technique.stix_id
    })

    SET
        t.mitre_id = technique.mitre_id,
        t.name = technique.name,
        t.description = technique.description,
        t.tactics = technique.tactics
    """

    tx.run(query, techniques=techniques)


# ============================================================
# Import Malware
# ============================================================

def import_malware(tx, malware):

    query = """
    UNWIND $malware AS item

    MERGE (m:Malware {
        stix_id: item.stix_id
    })

    SET
        m.name = item.name,
        m.description = item.description
    """

    tx.run(query, malware=malware)


# ============================================================
# Import Tools
# ============================================================

def import_tools(tx, tools):

    query = """
    UNWIND $tools AS item

    MERGE (t:Tool {
        stix_id: item.stix_id
    })

    SET
        t.name = item.name,
        t.description = item.description
    """

    tx.run(query, tools=tools)


# ============================================================
# Import Campaigns
# ============================================================

def import_campaigns(tx, campaigns):

    query = """
    UNWIND $campaigns AS item

    MERGE (c:Campaign {
        stix_id: item.stix_id
    })

    SET
        c.name = item.name,
        c.description = item.description
    """

    tx.run(query, campaigns=campaigns)


# ============================================================
# Create Tactic nodes
# ============================================================

def create_tactics(tx, techniques):

    tactics = set()

    for technique in techniques:

        for tactic in technique.get("tactics", []):

            tactics.add(tactic)

    tactic_list = [
        {"name": tactic}
        for tactic in tactics
    ]

    query = """
    UNWIND $tactics AS tactic

    MERGE (t:Tactic {
        name: tactic.name
    })
    """

    tx.run(query, tactics=tactic_list)


# ============================================================
# Connect Techniques to Tactics
# ============================================================

def connect_techniques_to_tactics(tx, techniques):

    pairs = []

    for technique in techniques:

        for tactic in technique.get("tactics", []):

            pairs.append({
                "technique_stix_id": technique["stix_id"],
                "tactic": tactic
            })

    query = """
    UNWIND $pairs AS pair

    MATCH (technique:Technique {
        stix_id: pair.technique_stix_id
    })

    MATCH (tactic:Tactic {
        name: pair.tactic
    })

    MERGE (technique)-[:BELONGS_TO]->(tactic)
    """

    tx.run(query, pairs=pairs)


# ============================================================
# Import STIX relationships
# ============================================================

def import_relationships(tx, relationships, valid_ids):

    valid_relationships = []

    for relationship in relationships:

        source = relationship.get("source_ref")
        target = relationship.get("target_ref")

        if source in valid_ids and target in valid_ids:

            relationship_type = (
                relationship.get("relationship_type", "RELATED_TO")
                .upper()
                .replace("-", "_")
                .replace(" ", "_")
            )

            valid_relationships.append({
                "source_ref": source,
                "target_ref": target,
                "relationship_type": relationship_type
            })

    print(
        f"Valid relationships to import: "
        f"{len(valid_relationships)}"
    )

    query = """
    UNWIND $relationships AS rel

    MATCH (source {
        stix_id: rel.source_ref
    })

    MATCH (target {
        stix_id: rel.target_ref
    })

    MERGE (source)-[r:$(rel.relationship_type)]->(target)
    """

    tx.run(
        query,
        relationships=valid_relationships
    )


# ============================================================
# Main
# ============================================================

def main():

    data = load_mitre_data()

    techniques = data["attack_patterns"]
    actors = data["threat_actors"]
    malware = data["malware"]
    tools = data["tools"]
    campaigns = data["campaigns"]
    relationships = data["relationships"]

    print()
    print("Data to import:")
    print("-----------------------------")
    print("Techniques :", len(techniques))
    print("Threat Actors:", len(actors))
    print("Malware    :", len(malware))
    print("Tools      :", len(tools))
    print("Campaigns  :", len(campaigns))
    print("Relationships:", len(relationships))

    # Build set of valid STIX IDs
    valid_ids = set()

    for item in techniques:
        valid_ids.add(item["stix_id"])

    for item in actors:
        valid_ids.add(item["stix_id"])

    for item in malware:
        valid_ids.add(item["stix_id"])

    for item in tools:
        valid_ids.add(item["stix_id"])

    for item in campaigns:
        valid_ids.add(item["stix_id"])

    print()
    print("Connecting to Neo4j...")

    driver.verify_connectivity()

    print("✅ Neo4j connection successful.")

    with driver.session(database=NEO4J_DATABASE) as session:

        # -----------------------------------------
        # Constraints
        # -----------------------------------------

        print("\nCreating constraints...")

        session.execute_write(
            create_constraints
        )

        print("✅ Constraints created.")

        # -----------------------------------------
        # Nodes
        # -----------------------------------------

        print("\nImporting Threat Actors...")

        session.execute_write(
            import_threat_actors,
            actors
        )

        print("✅ Threat Actors imported.")

        print("\nImporting Techniques...")

        session.execute_write(
            import_techniques,
            techniques
        )

        print("✅ Techniques imported.")

        print("\nImporting Malware...")

        session.execute_write(
            import_malware,
            malware
        )

        print("✅ Malware imported.")

        print("\nImporting Tools...")

        session.execute_write(
            import_tools,
            tools
        )

        print("✅ Tools imported.")

        print("\nImporting Campaigns...")

        session.execute_write(
            import_campaigns,
            campaigns
        )

        print("✅ Campaigns imported.")

        # -----------------------------------------
        # Tactics
        # -----------------------------------------

        print("\nCreating Tactics...")

        session.execute_write(
            create_tactics,
            techniques
        )

        print("✅ Tactics created.")

        print("\nConnecting Techniques → Tactics...")

        session.execute_write(
            connect_techniques_to_tactics,
            techniques
        )

        print("✅ Technique-Tactic relationships created.")

        # -----------------------------------------
        # STIX relationships
        # -----------------------------------------

        print("\nImporting MITRE relationships...")

        session.execute_write(
            import_relationships,
            relationships,
            valid_ids
        )

        print("✅ MITRE relationships imported.")

    driver.close()

    print()
    print("=" * 60)
    print("🎉 MITRE KNOWLEDGE GRAPH IMPORT COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()