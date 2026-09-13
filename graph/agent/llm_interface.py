import json
from pathlib import Path


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

INPUT_FILE = (
    PROJECT_ROOT
    / "data"
    / "retrieval"
    / "graph_agent_result.json"
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
    / "llm_prompt.json"
)


# ============================================================
# LLM INTERFACE
# ============================================================

class LLMInterface:
    """
    Provider-independent interface between the Graph Agent
    and an LLM.

    The Graph Agent supplies evidence.

    The LLM receives:
        - user query
        - MITRE techniques
        - graph relationships
        - attack paths
        - retrieved evidence
        - grounded context

    The LLM is responsible for reasoning over this evidence.

    This class currently builds the prompt only.
    An actual LLM provider can be connected later.
    """

    def __init__(self):

        self.system_prompt = """
You are a cybersecurity threat intelligence analyst.

You must answer using the evidence provided by the
GraphRAG retrieval system.

Rules:

1. Use retrieved evidence as the primary source.
2. Do not invent threat actors, techniques, vulnerabilities,
   relationships, or attack paths.
3. Clearly distinguish retrieved facts from inference.
4. Reference MITRE ATT&CK technique IDs when available.
5. Explain why the retrieved evidence supports the answer.
6. If the evidence is insufficient, explicitly state that.
7. Do not recommend destructive or unauthorized actions.
8. Prefer concise, evidence-grounded cybersecurity analysis.
""".strip()

    # ========================================================
    # LOAD GRAPH AGENT RESULT
    # ========================================================

    def load_graph_result(
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
    # BUILD USER PROMPT
    # ========================================================

    def build_user_prompt(
        self,
        graph_result
    ):

        query = graph_result.get(
            "query",
            ""
        )

        techniques = graph_result.get(
            "techniques",
            []
        )

        relationships = graph_result.get(
            "relationships",
            []
        )

        attack_paths = graph_result.get(
            "attack_paths",
            []
        )

        evidence = graph_result.get(
            "evidence",
            []
        )

        llm_context = graph_result.get(
            "llm_context",
            ""
        )

        # ----------------------------------------------------
        # Technique section
        # ----------------------------------------------------

        technique_text = []

        for technique in techniques:

            technique_text.append(
                {
                    "name": technique.get(
                        "name"
                    ),

                    "mitre_id": technique.get(
                        "mitre_id"
                    ),

                    "type": technique.get(
                        "type"
                    ),

                    "description": technique.get(
                        "description"
                    )
                }
            )

        # ----------------------------------------------------
        # Relationship section
        # ----------------------------------------------------

        relationship_text = []

        for relationship in relationships[
            :50
        ]:

            relationship_text.append(
                {
                    "source": relationship.get(
                        "source"
                    ),

                    "relationship": (
                        relationship.get(
                            "relationship"
                        )
                    ),

                    "direction": relationship.get(
                        "direction"
                    )
                }
            )

        # ----------------------------------------------------
        # Attack path section
        # ----------------------------------------------------

        path_text = []

        for path in attack_paths[
            :20
        ]:

            path_text.append(
                {
                    "start_entity": (
                        path.get(
                            "start_entity"
                        )
                    ),

                    "path": path.get(
                        "path"
                    )
                }
            )

        # ----------------------------------------------------
        # Build structured prompt
        # ----------------------------------------------------

        prompt = f"""
CYBERSECURITY THREAT INTELLIGENCE QUERY

USER QUERY:
{query}


RETRIEVED MITRE ATT&CK TECHNIQUES:
{json.dumps(
    technique_text,
    indent=2,
    ensure_ascii=False
)}


GRAPH RELATIONSHIPS:
{json.dumps(
    relationship_text,
    indent=2,
    ensure_ascii=False
)}


MULTI-HOP ATTACK PATHS:
{json.dumps(
    path_text,
    indent=2,
    ensure_ascii=False
)}


RETRIEVED EVIDENCE:
{json.dumps(
    evidence,
    indent=2,
    ensure_ascii=False,
    default=str
)}


GRAPH-RAG CONTEXT:
{llm_context}


TASK:

Analyze the query using the retrieved GraphRAG evidence.

Provide the response using this structure:

1. Threat Intelligence Summary
2. Relevant MITRE ATT&CK Techniques
3. Graph-Based Relationships
4. Observed / Retrieved Attack Paths
5. Evidence-Based Reasoning
6. Confidence and Evidence Limitations
7. Recommended Defensive Considerations

Do not introduce facts that are unsupported by the
retrieved evidence.
""".strip()

        return prompt

    # ========================================================
    # BUILD COMPLETE LLM REQUEST
    # ========================================================

    def build_request(
        self,
        graph_result
    ):

        user_prompt = self.build_user_prompt(
            graph_result
        )

        request = {

            "system_prompt": (
                self.system_prompt
            ),

            "user_prompt": user_prompt,

            "query": graph_result.get(
                "query"
            ),

            "source": "GraphAgent",

            "retrieval": graph_result.get(
                "retrieval",
                {}
            ),

            "evidence_statistics": (
                graph_result.get(
                    "statistics",
                    {}
                )
            )
        }

        return request

    # ========================================================
    # SAVE REQUEST
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
    print("LLM INTERFACE TEST")
    print("=" * 70)

    # --------------------------------------------------------
    # Initialize
    # --------------------------------------------------------

    interface = LLMInterface()

    # --------------------------------------------------------
    # Load Graph Agent output
    # --------------------------------------------------------

    print("\n[1] Loading Graph Agent result...")

    graph_result = (
        interface.load_graph_result()
    )

    print(
        f"    Query: "
        f"{graph_result.get('query')}"
    )

    # --------------------------------------------------------
    # Build LLM request
    # --------------------------------------------------------

    print(
        "\n[2] Building LLM request..."
    )

    request = interface.build_request(
        graph_result
    )

    # --------------------------------------------------------
    # Statistics
    # --------------------------------------------------------

    print(
        "\n[3] LLM request statistics"
    )

    print(
        f"    Techniques: "
        f"{len(graph_result.get('techniques', []))}"
    )

    print(
        f"    Relationships: "
        f"{len(graph_result.get('relationships', []))}"
    )

    print(
        f"    Attack paths: "
        f"{len(graph_result.get('attack_paths', []))}"
    )

    print(
        f"    Evidence items: "
        f"{len(graph_result.get('evidence', []))}"
    )

    print(
        f"    Prompt characters: "
        f"{len(request['user_prompt'])}"
    )

    # --------------------------------------------------------
    # Preview
    # --------------------------------------------------------

    print("\n")
    print("-" * 70)
    print("LLM PROMPT PREVIEW")
    print("-" * 70)

    print(
        request["user_prompt"][
            :5000
        ]
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    output = interface.save_request(
        request
    )

    print("\n")
    print("=" * 70)
    print("LLM INTERFACE COMPLETE")
    print("=" * 70)

    print(
        "\nSaved LLM request to:"
    )

    print(output)