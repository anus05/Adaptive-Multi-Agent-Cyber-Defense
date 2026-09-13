import json
from pathlib import Path

from neo4j import GraphDatabase
from dotenv import load_dotenv
import os


# --------------------------------------------------
# Load environment variables
# --------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")


NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")


# --------------------------------------------------
# NVD file
# --------------------------------------------------

NVD_FILE = PROJECT_ROOT / "data" / "nvd" / "nvd_sample.json"


# --------------------------------------------------
# Neo4j connection
# --------------------------------------------------

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USERNAME, NEO4J_PASSWORD)
)


# --------------------------------------------------
# Create constraints
# --------------------------------------------------

def create_constraints():

    with driver.session(database=NEO4J_DATABASE) as session:

        session.run("""
            CREATE CONSTRAINT cve_id_unique IF NOT EXISTS
            FOR (c:CVE)
            REQUIRE c.cve_id IS UNIQUE
        """)

        session.run("""
            CREATE CONSTRAINT weakness_name_unique IF NOT EXISTS
            FOR (w:Weakness)
            REQUIRE w.name IS UNIQUE
        """)

    print("✅ Constraints created")


# --------------------------------------------------
# Load CVE
# --------------------------------------------------

def load_cve(cve):

    with driver.session(database=NEO4J_DATABASE) as session:

        session.run(
            """
            MERGE (c:CVE {
                cve_id: $cve_id
            })

            SET c.description = $description,
                c.cvss_score = $cvss_score,
                c.cvss_severity = $cvss_severity,
                c.published = $published,
                c.last_modified = $last_modified,
                c.references = $references
            """,
            cve_id=cve["cve_id"],
            description=cve["description"],
            cvss_score=cve["cvss_score"],
            cvss_severity=cve["cvss_severity"],
            published=cve["published"],
            last_modified=cve["last_modified"],
            references=cve["references"]
        )


# --------------------------------------------------
# Load weaknesses / CWE
# --------------------------------------------------

def load_weaknesses(cve):

    with driver.session(database=NEO4J_DATABASE) as session:

        for weakness in cve["weaknesses"]:

            session.run(
                """
                MERGE (w:Weakness {
                    name: $name
                })

                WITH w

                MATCH (c:CVE {
                    cve_id: $cve_id
                })

                MERGE (c)-[:HAS_WEAKNESS]->(w)
                """,
                name=weakness,
                cve_id=cve["cve_id"]
            )


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    print("Loading NVD data...")

    if not NVD_FILE.exists():

        print("❌ NVD file not found:")
        print(NVD_FILE)
        return

    with open(
        NVD_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        cves = json.load(file)

    print("CVEs found:", len(cves))

    create_constraints()

    for index, cve in enumerate(cves, start=1):

        load_cve(cve)
        load_weaknesses(cve)

        print(
            f"  [{index}/{len(cves)}] "
            f"{cve['cve_id']}"
        )

    print()
    print("✅ NVD import completed")


if __name__ == "__main__":

    try:

        main()

    finally:

        driver.close()