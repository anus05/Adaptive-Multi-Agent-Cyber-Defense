import json
import sys
from pathlib import Path


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# PATHS
# ============================================================

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "retrieval"
    / "compressed_context.json"
)

OUTPUT_DIR = (
    PROJECT_ROOT
    / "data"
    / "retrieval"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "llm_reasoning_request.json"
)


# ============================================================
# LLM REASONER
# ============================================================

class LLMReasoner:
    """
    Evidence-grounded LLM reasoning layer.

    GraphRAG provides the evidence.
    LLM performs reasoning over that evidence.

    This class currently prepares the request.
    It does not execute security actions.
    """

    def __init__(self):

        self.system_prompt = """
You are an evidence-grounded cybersecurity
threat intelligence analyst.

Analyze the user's query using only the
GraphRAG evidence provided.

Rules:

1. Treat retrieved evidence as the primary source.
2. Do not invent entities, techniques, malware,
   vulnerabilities, relationships, or attack paths.
3. Distinguish retrieved facts from inference.
4. Use MITRE ATT&CK IDs when available.
5. Do not claim an attack occurred unless evidence
   establishes that fact.
6. If evidence is insufficient, explicitly say so.
7. Confidence must reflect evidence strength.
8. Provide defensive considerations only.
9. Do not perform or recommend destructive
   autonomous actions.
""".strip()


    # ========================================================
    # LOAD
    # ========================================================

    def load_context(
        self,
        input_file=INPUT_FILE
    ):

        with open(
            input_file,
            "r",
            encoding="utf-8"
        ) as f:

            return json.load(f)


    # ========================================================
    # BUILD PROMPT
    # ========================================================

    def build_prompt(
        self,
        context
    ):

        query = context.get(
            "query",
            ""
        )

        # ----------------------------------------------------
        # IMPORTANT:
        #
        # Use the already-compressed GraphRAG context.
        #
        # Do NOT append the same techniques,
        # relationships and paths again.
        # ----------------------------------------------------

        graph_context = context.get(
            "llm_context",
            ""
        )

        prompt = f"""
CYBERSECURITY THREAT INTELLIGENCE ANALYSIS

USER QUERY:
{query}


GROUNDING SOURCE:
The following information was retrieved by the
Hybrid GraphRAG system using Neo4j and ChromaDB.

Use this evidence as the factual basis for your analysis.

------------------------------------------------------------
GRAPH-RAG EVIDENCE
------------------------------------------------------------

{graph_context}

------------------------------------------------------------
ANALYSIS TASK
------------------------------------------------------------

Analyze the user's cybersecurity query using the
GraphRAG evidence above.

Return the answer using exactly these sections:

1. Threat Intelligence Summary

Briefly answer the user's query using retrieved evidence.

2. Relevant MITRE ATT&CK Techniques

For each relevant technique provide:

- Technique name
- MITRE ATT&CK ID
- Why it is relevant

3. Graph-Based Relationships

Describe the important relationships explicitly supported
by the retrieved graph.

4. Multi-Hop Attack Paths

Describe meaningful paths present in the graph.

Clearly distinguish graph evidence from inference.

5. Evidence-Based Reasoning

Explain how the retrieved evidence supports the analysis.

6. Confidence

Return:

HIGH
MEDIUM
or
LOW

Then explain the basis for the confidence level.

7. Evidence Limitations

Explain what the retrieved evidence does NOT establish.

8. Defensive Considerations

Provide defensive, monitoring, detection, or mitigation
considerations based on the retrieved evidence.

STRICT GROUNDING:

Do not introduce unsupported facts.

Do not assume that a MITRE ATT&CK technique was observed
in a real attack merely because it exists in the knowledge
graph.

Do not invent relationships.

Do not invent threat actors.

Do not invent attack chains.

If the evidence is insufficient, explicitly state that.
""".strip()

        return prompt


    # ========================================================
    # BUILD REQUEST
    # ========================================================

    def build_request(
        self,
        context
    ):

        prompt = self.build_prompt(
            context
        )

        request = {

            "provider": (
                "TO_BE_CONFIGURED"
            ),

            "model": (
                "TO_BE_CONFIGURED"
            ),

            "system_prompt": (
                self.system_prompt
            ),

            "user_prompt": prompt,

            "query": context.get(
                "query"
            ),

            "source": (
                "GraphAgent + Hybrid GraphRAG"
            ),

            "grounding": {

                "knowledge_graph": (
                    "Neo4j"
                ),

                "vector_database": (
                    "ChromaDB"
                ),

                "retrieval": (
                    "Hybrid GraphRAG"
                ),

                "evidence_compression": True

            },

            "statistics": context.get(
                "statistics",
                {}
            )
        }

        return request


    # ========================================================
    # SAVE
    # ========================================================

    def save_request(
        self,
        request,
        output_file=OUTPUT_FILE
    ):

        with open(
            output_file,
            "w",
            encoding="utf-8"
        ) as f:

            json.dump(
                request,
                f,
                indent=2,
                ensure_ascii=False,
                default=str
            )

        return output_file


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    print("=" * 70)
    print("OPTIMIZED LLM REASONER TEST")
    print("=" * 70)


    # --------------------------------------------------------
    # Initialize
    # --------------------------------------------------------

    reasoner = LLMReasoner()


    # --------------------------------------------------------
    # Load
    # --------------------------------------------------------

    print(
        "\n[1] Loading compressed GraphRAG context..."
    )

    context = reasoner.load_context()

    print(
        f"    Query: "
        f"{context.get('query')}"
    )

    original_context_size = len(
        context.get(
            "llm_context",
            ""
        )
    )

    print(
        f"    GraphRAG context: "
        f"{original_context_size} characters"
    )


    # --------------------------------------------------------
    # Build
    # --------------------------------------------------------

    print(
        "\n[2] Building optimized LLM request..."
    )

    request = reasoner.build_request(
        context
    )


    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    prompt_size = len(
        request["user_prompt"]
    )

    print(
        "\n[3] Request statistics"
    )

    print(
        f"    GraphRAG context: "
        f"{original_context_size}"
    )

    print(
        f"    Final prompt: "
        f"{prompt_size}"
    )

    print(
        f"    Techniques: "
        f"{len(context.get('techniques', []))}"
    )

    print(
        f"    Relationships: "
        f"{len(context.get('relationships', []))}"
    )

    print(
        f"    Attack paths: "
        f"{len(context.get('attack_paths', []))}"
    )


    # --------------------------------------------------------
    # Preview
    # --------------------------------------------------------

    print("\n")
    print("-" * 70)
    print("OPTIMIZED LLM PROMPT PREVIEW")
    print("-" * 70)

    print(
        request["user_prompt"][
            :5000
        ]
    )


    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    output = reasoner.save_request(
        request
    )

    print("\n")
    print("=" * 70)
    print("OPTIMIZED LLM REASONER COMPLETE")
    print("=" * 70)

    print(
        "\nSaved request to:"
    )

    print(output)