from graph.retrieval.vector_store import VectorStore


# ============================================================
# VECTOR RETRIEVER
# ============================================================

class VectorRetriever:

    def __init__(self):

        self.store = VectorStore()


    # ========================================================
    # Semantic Search
    # ========================================================

    def search(
        self,
        query,
        top_k=5
    ):

        query_embedding = (
            self.store.model.encode(
                [query]
            ).tolist()
        )

        results = self.store.collection.query(
            query_embeddings=query_embedding,
            n_results=top_k
        )

        formatted = []

        documents = results.get(
            "documents",
            [[]]
        )[0]

        metadatas = results.get(
            "metadatas",
            [[]]
        )[0]

        distances = results.get(
            "distances",
            [[]]
        )[0]

        for i in range(
            len(documents)
        ):

            formatted.append({

                "rank": i + 1,

                "document": documents[i],

                "metadata": metadatas[i],

                "distance": distances[i]
            })

        return formatted


# ============================================================
# TEST
# ============================================================

def main():

    print()
    print(
        "#" * 60
    )

    print(
        "# VECTOR RETRIEVAL TEST"
    )

    print(
        "#" * 60
    )


    retriever = VectorRetriever()


    # --------------------------------------------------------
    # Test Query
    # --------------------------------------------------------

    query = (
        "techniques used by attackers "
        "for command execution"
    )


    print()
    print(
        f"Query: {query}"
    )

    print()


    results = retriever.search(
        query,
        top_k=5
    )


    # --------------------------------------------------------
    # Display Results
    # --------------------------------------------------------

    for result in results:

        print(
            "=" * 60
        )

        print(
            f"Rank: "
            f"{result['rank']}"
        )

        print(
            f"Name: "
            f"{result['metadata'].get('name')}"
        )

        print(
            f"Type: "
            f"{result['metadata'].get('type')}"
        )

        print(
            f"MITRE ID: "
            f"{result['metadata'].get('mitre_id')}"
        )

        print(
            f"Distance: "
            f"{result['distance']:.4f}"
        )

        print()

        print(
            result["document"][:800]
        )

        print()


    print(
        "=" * 60
    )

    print(
        "✅ Vector retrieval test completed"
    )


if __name__ == "__main__":

    main()