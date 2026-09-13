import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import chromadb
from sentence_transformers import SentenceTransformer


# ============================================================
# PROJECT PATHS
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

VECTOR_DB_DIR = (
    PROJECT_ROOT
    / "data"
    / "vector_db"
)


# ============================================================
# VECTOR STORE
# ============================================================

class VectorStore:
    """
    Vector Store interface wrapping ChromaDB persistent client
    and SentenceTransformers embedding model.
    """

    def __init__(
        self,
        db_path: Optional[Path] = None,
        collection_name: str = "cybersecurity_knowledge",
        model_name: str = "all-MiniLM-L6-v2"
    ):
        if db_path is None:
            db_path = VECTOR_DB_DIR

        self.db_path = Path(db_path)
        self.collection_name = collection_name
        self.model_name = model_name

        print(f"Loading embedding model '{self.model_name}'...")
        self.model = SentenceTransformer(self.model_name)

        print(f"Connecting to ChromaDB at '{self.db_path}'...")
        self.client = chromadb.PersistentClient(
            path=str(self.db_path)
        )

        self.collection = self.client.get_or_create_collection(
            name=self.collection_name
        )

        print(f"Vector Store initialized with collection '{self.collection_name}'.")

    # ========================================================
    # SEMANTIC SEARCH
    # ========================================================

    def search(
        self,
        query: str,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Execute semantic vector search.

        Returns a list of dictionaries with direct flat fields:
        - name
        - mitre_id
        - stix_id
        - type
        - external_id
        - id
        - description
        - document
        - distance
        - rank
        """
        if not query or not query.strip():
            return []

        query_embedding = self.model.encode([query]).tolist()

        results = self.collection.query(
            query_embeddings=query_embedding,
            n_results=top_k
        )

        documents = results.get("documents", [[]])[0]
        metadatas = results.get("metadatas", [[]])[0]
        distances = results.get("distances", [[]])[0]
        ids = results.get("ids", [[]])[0]

        formatted_results = []

        for i in range(len(documents)):
            doc = documents[i] if i < len(documents) else ""
            meta = metadatas[i] if (metadatas and i < len(metadatas) and metadatas[i]) else {}
            dist = distances[i] if (distances and i < len(distances)) else None
            item_id = ids[i] if (ids and i < len(ids)) else f"doc_{i}"

            name = meta.get("name", "")
            mitre_id = meta.get("mitre_id") or meta.get("external_id") or ""
            stix_id = meta.get("stix_id") or item_id
            object_type = meta.get("type") or ""

            description = meta.get("description") or ""
            if not description and "Description:" in doc:
                parts = doc.split("Description:", 1)
                description = parts[1].strip()

            formatted_results.append({
                "name": name,
                "mitre_id": mitre_id,
                "stix_id": stix_id,
                "type": object_type,
                "external_id": mitre_id,
                "id": item_id,
                "description": description,
                "document": doc,
                "distance": dist,
                "rank": i + 1,
            })

        return formatted_results


# ============================================================
# MAIN TEST
# ============================================================

def main():
    print()
    print("=" * 60)
    print("VECTOR STORE TEST")
    print("=" * 60)

    store = VectorStore()
    query = "techniques used by attackers for command execution"
    print(f"\nQuery: {query}\n")

    results = store.search(query, top_k=5)
    for result in results:
        print(f"Rank {result['rank']}: {result['name']} | {result['mitre_id']} | distance={result['distance']:.4f}")

    print("\n[OK] Vector store test completed")


if __name__ == "__main__":
    main()