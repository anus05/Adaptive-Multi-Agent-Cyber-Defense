import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase


# ============================================================
# PROJECT CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE)


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
# GRAPH RETRIEVER
# ============================================================

class GraphRetriever:

    def __init__(self):
        self.driver = None
        try:
            self.driver = GraphDatabase.driver(
                NEO4J_URI,
                auth=(
                    NEO4J_USERNAME,
                    NEO4J_PASSWORD
                )
            )
            self.driver.verify_connectivity()
            print(
                "[OK] Graph Retriever connected to Neo4j"
            )
        except Exception as e:
            self.driver = None
            print(
                f"[WARNING] Graph Retriever could not connect to Neo4j ({e}). Running in vector-only fallback mode."
            )


    # ========================================================
    # Close connection
    # ========================================================

    def close(self):
        if self.driver:
            self.driver.close()


    # ========================================================
    # Find entity by name
    # ========================================================

    def find_entity(
        self,
        name
    ):
        if not self.driver:
            return []

        query = """
        MATCH (n)
        WHERE toLower(n.name) = toLower($name)
        RETURN
            labels(n) AS labels,
            n.name AS name,
            n.stix_id AS stix_id,
            n.external_id AS external_id
        LIMIT 10
        """

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                query,
                name=name
            )

            return [
                record.data()
                for record in result
            ]


    # ========================================================
    # Get direct neighbors
    # ========================================================

    def get_neighbors(
        self,
        name
    ):
        if not self.driver:
            return []

        query = """
        MATCH (n)-[r]->(m)
        WHERE toLower(n.name) = toLower($name)

        RETURN
            labels(n) AS source_labels,
            n.name AS source,
            type(r) AS relationship,
            labels(m) AS target_labels,
            m.name AS target,
            m.stix_id AS target_stix_id,
            m.external_id AS target_external_id

        ORDER BY target
        LIMIT 50
        """

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                query,
                name=name
            )

            return [
                record.data()
                for record in result
            ]


    # ========================================================
    # Reverse neighbors
    # ========================================================

    def get_reverse_neighbors(
        self,
        name
    ):
        if not self.driver:
            return []

        query = """
        MATCH (n)<-[r]-(m)
        WHERE toLower(n.name) = toLower($name)

        RETURN
            labels(m) AS source_labels,
            m.name AS source,
            type(r) AS relationship,
            labels(n) AS target_labels,
            n.name AS target,
            m.stix_id AS source_stix_id,
            m.external_id AS source_external_id

        ORDER BY source
        LIMIT 50
        """

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                query,
                name=name
            )

            return [
                record.data()
                for record in result
            ]


    # ========================================================
    # Multi-hop attack path
    # ========================================================

    def get_attack_paths(
        self,
        name,
        max_hops=3
    ):
        if not self.driver:
            return []

        # Keep the maximum traversal controlled.
        max_hops = min(
            max(1, max_hops),
            5
        )

        query = f"""
        MATCH path =
            (start)-[*1..{max_hops}]->(target)

        WHERE
            toLower(start.name)
            = toLower($name)

        RETURN
            [node IN nodes(path) |
                {{
                    labels: labels(node),
                    name: node.name,
                    stix_id: node.stix_id,
                    external_id: node.external_id
                }}
            ] AS nodes,

            [rel IN relationships(path) |
                type(rel)
            ] AS relationships

        LIMIT 100
        """

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                query,
                name=name
            )

            return [
                record.data()
                for record in result
            ]


    # ========================================================
    # Search by ATT&CK external ID
    # ========================================================

    def find_by_external_id(
        self,
        external_id
    ):
        if not self.driver:
            return []

        query = """
        MATCH (n)
        WHERE n.external_id = $external_id

        RETURN
            labels(n) AS labels,
            n.name AS name,
            n.stix_id AS stix_id,
            n.external_id AS external_id,
            n.description AS description

        LIMIT 10
        """

        with self.driver.session(
            database=NEO4J_DATABASE
        ) as session:

            result = session.run(
                query,
                external_id=external_id
            )

            return [
                record.data()
                for record in result
            ]



# ============================================================
# Pretty printer
# ============================================================

def print_results(
    title,
    results
):

    print()
    print("=" * 60)
    print(title)
    print("=" * 60)

    if not results:

        print(
            "No results found."
        )

        return

    for index, result in enumerate(
        results,
        start=1
    ):

        print()
        print(
            f"{index}.",
            result
        )


# ============================================================
# TEST
# ============================================================

def main():

    print()
    print("#" * 60)
    print("# GRAPH RETRIEVAL TEST")
    print("#" * 60)

    retriever = GraphRetriever()

    try:

        # ----------------------------------------------------
        # Test 1
        # ----------------------------------------------------

        results = retriever.find_entity(
            "J-magic Campaign"
        )

        print_results(
            "ENTITY SEARCH",
            results
        )

        # ----------------------------------------------------
        # Test 2
        # ----------------------------------------------------

        results = retriever.get_neighbors(
            "J-magic Campaign"
        )

        print_results(
            "DIRECT GRAPH NEIGHBORS",
            results
        )

        # ----------------------------------------------------
        # Test 3
        # ----------------------------------------------------

        results = retriever.get_reverse_neighbors(
            "J-magic Campaign"
        )

        print_results(
            "REVERSE GRAPH NEIGHBORS",
            results
        )

        # ----------------------------------------------------
        # Test 4
        # ----------------------------------------------------

        results = retriever.get_attack_paths(
            "J-magic Campaign",
            max_hops=3
        )

        print_results(
            "MULTI-HOP ATTACK PATHS",
            results
        )

        # ----------------------------------------------------
        # Test 5
        # ----------------------------------------------------

        results = retriever.find_by_external_id(
            "C0058"
        )

        print_results(
            "EXTERNAL ID SEARCH",
            results
        )

    finally:

        retriever.close()

        print()
        print(
            "[OK] Graph Retriever test completed"
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":

    main()