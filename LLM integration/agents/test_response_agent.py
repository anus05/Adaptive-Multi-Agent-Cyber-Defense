from orchestration.state import AgentState
from agents.response_agent import ResponseAgent


def main():
    print("=" * 60)
    print("RESPONSE AGENT TEST")
    print("=" * 60)

    state = AgentState(
        incident_id="INC-RESP-001",

        alert={
            "source": "test",
            "event": "Multiple failed SSH login attempts",
        },

        detection={
            "is_suspicious": True,
            "severity": "high",
            "behavior_summary": "Multiple failed SSH login attempts",
            "entities": ["SSH"],
            "observed_evidence": [
                "Multiple failed SSH login attempts"
            ],
            "inference": [
                "Possible credential attack activity"
            ],
            "reasoning": (
                "Repeated failed SSH authentication attempts "
                "may indicate suspicious activity."
            ),
            "confidence": 0.90,
            "limitations": [],
        },

        threat_intelligence={
            "status": "received",
            "source": "Member 2 GraphRAG API",
            "retrieved_context": {
                "evidence": [
                    {
                        "name": "Command and Scripting Interpreter",
                        "mitre_id": "T1059",
                        "source": "MITRE ATT&CK",
                    }
                ],
                "llm_context": (
                    "Retrieved cybersecurity knowledge "
                    "related to command execution."
                ),
                "statistics": {
                    "graph_entities": 5,
                    "relationships": 48,
                    "attack_paths": 7,
                    "evidence_items": 5,
                },
            },
            "evidence": [
                {
                    "name": "Command and Scripting Interpreter",
                    "mitre_id": "T1059",
                    "source": "MITRE ATT&CK",
                }
            ],
            "llm_context": (
                "Retrieved cybersecurity knowledge "
                "related to command execution."
            ),
            "statistics": {
                "graph_entities": 5,
                "relationships": 48,
                "attack_paths": 7,
                "evidence_items": 5,
            },
        },

        correlation={
            "correlations": [
                {
                    "observed_evidence": (
                        "Multiple failed SSH login attempts"
                    ),
                    "retrieved_entity": (
                        "Command and Scripting Interpreter"
                    ),
                    "retrieved_mitre_id": "T1059",
                    "relationship": (
                        "Insufficient direct correlation"
                    ),
                    "basis": (
                        "The observed failed login attempts do "
                        "not directly demonstrate command execution."
                    ),
                    "confidence": 0.0,
                }
            ],
            "attack_chain": [],
            "observed_behaviors": [
                "Multiple failed SSH login attempts"
            ],
            "retrieved_techniques": [
                "Command and Scripting Interpreter (T1059)"
            ],
            "inferences": [
                "Possible credential attack activity"
            ],
            "reasoning": (
                "There is insufficient direct evidence to "
                "correlate the failed SSH attempts with "
                "command execution."
            ),
            "confidence": 0.0,
            "limitations": [
                "Retrieved T1059 does not directly align "
                "with the observed failed login attempts."
            ],
        },
    )

    agent = ResponseAgent()

    print("\n[1] Running Response Agent...")

    state = agent.analyze(state)

    print("\n[2] Agent stage:")
    print(state.current_stage)

    print("\n[3] Response priority:")
    print(state.response.get("response_priority"))

    print("\n[4] Recommended actions:")
    print(state.response.get("recommended_actions"))

    print("\n[5] Immediate actions:")
    print(state.response.get("immediate_actions"))

    print("\n[6] Follow-up actions:")
    print(state.response.get("follow_up_actions"))

    print("\n[7] Human approval required:")
    print(state.response.get("human_approval_required"))

    print("\n[8] Execution status:")
    print(state.response.get("execution_status"))

    print("\n[9] Reasoning:")
    print(state.response.get("reasoning"))

    print("\n[10] Confidence:")
    print(state.response.get("confidence"))

    print("\n[11] Limitations:")
    print(state.response.get("limitations"))

    print("\n[12] Agent messages:")
    print(state.agent_messages)

    print("\n" + "=" * 60)
    print("RESPONSE AGENT TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()