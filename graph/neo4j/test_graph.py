import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase


# Load .env from project root
PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env")


URI = os.getenv("NEO4J_URI")
USERNAME = os.getenv("NEO4J_USERNAME")
PASSWORD = os.getenv("NEO4J_PASSWORD")
DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


driver = GraphDatabase.driver(
    URI,
    auth=(USERNAME, PASSWORD)
)


def create_test_graph(tx):
    query = """
    MERGE (actor:ThreatActor {
        name: "APT29"
    })

    MERGE (technique:Technique {
        mitre_id: "T1059.001",
        name: "PowerShell"
    })

    MERGE (actor)-[:USES]->(technique)

    RETURN actor.name AS actor,
           technique.mitre_id AS technique_id,
           technique.name AS technique_name
    """

    result = tx.run(query)

    return result.single()


def main():

    try:
        driver.verify_connectivity()

        print("✅ Connected to Neo4j")

        with driver.session(database=DATABASE) as session:

            record = session.execute_write(
                create_test_graph
            )

            print()
            print("Created Knowledge Graph:")
            print("------------------------")
            print("Threat Actor :", record["actor"])
            print("Technique ID :", record["technique_id"])
            print("Technique    :", record["technique_name"])

        print()
        print("✅ Test graph created successfully!")

    except Exception as e:
        print("❌ Error:", e)

    finally:
        driver.close()


if __name__ == "__main__":
    main()