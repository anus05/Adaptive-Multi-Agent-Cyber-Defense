from orchestration.state import AgentState
from agents.explanation_agent import ExplanationAgent


def main():
    print("=" * 60)
    print("EXPLANATION AGENT TEST")
    print("=" * 60)

    state = AgentState(
        incident_id="INC-EXP-001",

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
                        "The observed failed login attempts "
                        "do not directly demonstrate command execution."
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

        response={
            "response_priority": "high",
            "recommended_actions": [
                {
                    "action": (
                        "Review SSH server logs to identify "
                        "source IP addresses and attempted usernames."
                    ),
                    "reason": (
                        "This investigation can help identify "
                        "the source and scope of the activity."
                    ),
                    "priority": "high",
                    "type": "investigation",
                    "reversible": True,
                }
            ],
            "immediate_actions": [
                {
                    "action": (
                        "Review SSH authentication logs."
                    ),
                    "reason": (
                        "To investigate the suspicious login activity."
                    ),
                    "priority": "high",
                    "type": "investigation",
                    "reversible": True,
                }
            ],
            "follow_up_actions": [
                {
                    "action": (
                        "Strengthen SSH authentication controls."
                    ),
                    "reason": (
                        "To reduce the risk of future credential attacks."
                    ),
                    "priority": "medium",
                    "type": "hardening",
                    "reversible": True,
                }
            ],
            "human_approval_required": True,
            "execution_status": "recommendation_only",
            "reasoning": (
                "The recommendations focus on investigating "
                "and reducing the risk associated with repeated "
                "failed SSH login attempts."
            ),
            "confidence": 0.90,
            "limitations": [],
        },
    )

    agent = ExplanationAgent()

    print("\n[1] Running Explanation Agent...")

    state = agent.analyze(state)

    print("\n[2] Agent stage:")
    print(state.current_stage)

    print("\n[3] Summary:")
    print(state.explanation.get("summary"))

    print("\n[4] Observed evidence:")
    print(state.explanation.get("observed_evidence"))

    print("\n[5] Retrieved knowledge:")
    print(state.explanation.get("retrieved_knowledge"))

    print("\n[6] Correlation explanation:")
    print(state.explanation.get("correlation_explanation"))

    print("\n[7] Response explanation:")
    print(state.explanation.get("response_explanation"))

    print("\n[8] Inferences:")
    print(state.explanation.get("inferences"))

    print("\n[9] Limitations:")
    print(state.explanation.get("limitations"))

    print("\n[10] Confidence:")
    print(state.explanation.get("confidence"))

    print("\n[11] Agent messages:")
    print(state.agent_messages)

    print("\n" + "=" * 60)
    print("EXPLANATION AGENT TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()