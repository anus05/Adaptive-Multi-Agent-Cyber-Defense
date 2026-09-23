import os
import sys
from pathlib import Path
from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

load_dotenv(PROJECT_ROOT / ".env")

from neo4j import GraphDatabase

def main():
    uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
    username = os.getenv("NEO4J_USERNAME", "neo4j")
    password = os.getenv("NEO4J_PASSWORD", "")
    database = os.getenv("NEO4J_DATABASE", "neo4j")

    print(f"Connecting to Neo4j at {uri} (Database: {database})...")

    try:
        driver = GraphDatabase.driver(uri, auth=(username, password))
        driver.verify_connectivity()
        print("[OK] Neo4j connection successful!")
        
        with driver.session(database=database) as session:
            result = session.run("MATCH (n) RETURN count(n) AS node_count")
            record = result.single()
            print(f"Total Nodes in Knowledge Graph: {record['node_count']}")
        driver.close()
    except Exception as e:
        print(f"[FAILED] Neo4j connection failed: {e}")
        print("Note: If Neo4j is offline, GraphRAG will automatically fall back to ChromaDB vector search.")


if __name__ == "__main__":
    main()
