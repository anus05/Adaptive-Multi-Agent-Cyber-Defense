import json
import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

load_dotenv(PROJECT_ROOT / ".env")


# ============================================================
# NEO4J CONFIGURATION
# ============================================================

NEO4J_URI = os.getenv("NEO4J_URI")
NEO4J_USERNAME = os.getenv("NEO4J_USERNAME")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD")
NEO4J_DATABASE = os.getenv(
    "NEO4J_DATABASE",
    "neo4j"
)


# ============================================================
# NVD FILE
# ============================================================

NVD_FILE = (
    PROJECT_ROOT
    / "data"
    / "nvd"
    / "nvd_sample.json"
)


# ============================================================
# NEO4J DRIVER
# ============================================================

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(
        NEO4J_USERNAME,
        NEO4J_PASSWORD
    )
)


# ============================================================
# CREATE CONSTRAINT
# ============================================================

def create_constraint():

    with driver.session(
        database=NEO4J_DATABASE
    ) as session:

        session.run("""
            CREATE CONSTRAINT software_cpe_unique
            IF NOT EXISTS
            FOR (s:Software)
            REQUIRE s.cpe IS UNIQUE
        """)

    print("✅ Software constraint ready")


# ============================================================
# IMPORT CVE + SOFTWARE + AFFECTS
# ============================================================

def import_cve_products(cve):

    query = """
    MERGE (c:CVE {
        cve_id: $cve_id
    })

    WITH c

    UNWIND $products AS p

    MERGE (s:Software {
        cpe: p.cpe
    })

    SET s.vendor = p.vendor,
        s.product = p.product,
        s.version = p.version

    MERGE (c)-[:AFFECTS]->(s)

    RETURN count(s) AS products_created
    """

    with driver.session(
        database=NEO4J_DATABASE
    ) as session:

        result = session.run(
            query,
            cve_id=cve["cve_id"],
            products=cve.get(
                "products",
                []
            )
        )

        record = result.single()

        if record:
            return record["products_created"]

    return 0


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 60)
    print("NVD → NEO4J PRODUCT IMPORT")
    print("=" * 60)

    # --------------------------------------------------------
    # Check JSON file
    # --------------------------------------------------------

    if not NVD_FILE.exists():

        print()
        print("❌ NVD file not found:")
        print(NVD_FILE)

        return

    # --------------------------------------------------------
    # Load JSON
    # --------------------------------------------------------

    with open(
        NVD_FILE,
        "r",
        encoding="utf-8"
    ) as file:

        cves = json.load(file)

    print()
    print(
        "CVEs found:",
        len(cves)
    )

    # --------------------------------------------------------
    # Neo4j constraint
    # --------------------------------------------------------

    create_constraint()

    # --------------------------------------------------------
    # Import
    # --------------------------------------------------------

    total_products = 0
    total_relationships = 0

    for index, cve in enumerate(
        cves,
        start=1
    ):

        products = cve.get(
            "products",
            []
        )

        count = import_cve_products(
            cve
        )

        total_products += len(products)
        total_relationships += count

        print(
            f"[{index}/{len(cves)}] "
            f"{cve['cve_id']} → "
            f"{len(products)} products"
        )

    # --------------------------------------------------------
    # Result
    # --------------------------------------------------------

    print()
    print("=" * 60)

    print(
        "Product records processed:",
        total_products
    )

    print(
        "AFFECTS relationships processed:",
        total_relationships
    )

    print(
        "✅ NVD product import completed"
    )

    print("=" * 60)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except Exception as e:

        print()
        print("❌ Import failed:")
        print(e)

    finally:

        driver.close()