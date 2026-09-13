import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase


# Project root:
# D:\My Projects\project
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Explicitly load .env from project root
ENV_FILE = PROJECT_ROOT / ".env"

print("Loading .env from:", ENV_FILE)
print("File exists:", ENV_FILE.exists())

load_dotenv(ENV_FILE)


NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


print("URI:", NEO4J_URI)
print("Username:", NEO4J_USERNAME)
print("Database:", NEO4J_DATABASE)


if not NEO4J_URI:
    raise ValueError(
        "NEO4J_URI was not loaded. Check your .env file."
    )

if not NEO4J_USERNAME:
    raise ValueError(
        "NEO4J_USERNAME was not loaded. Check your .env file."
    )

if not NEO4J_PASSWORD:
    raise ValueError(
        "NEO4J_PASSWORD was not loaded. Check your .env file."
    )


driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)


def test_connection():
    try:
        driver.verify_connectivity()

        print()
        print("===================================")
        print("✅ Neo4j connection successful!")
        print("===================================")
        print("URI:", NEO4J_URI)
        print("Database:", NEO4J_DATABASE)

    except Exception as e:
        print()
        print("❌ Neo4j connection failed!")
        print("Error:", e)


if __name__ == "__main__":
    test_connection()
    driver.close()