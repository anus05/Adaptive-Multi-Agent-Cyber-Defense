from orchestration.state import AgentState
from agents.attack_correlation_agent import AttackCorrelationAgent


def main():
    print("=" * 60)
    print("ATTACK CORRELATION AGENT TEST")
    print("=" * 60)

    # Create a test state containing the output
    # of the Detection Agent and Threat Intelligence Agent.
    state = AgentState(
        incident_id="INC-CORR-001",
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
                        "source": "MITRE ATT&CK"
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
                    "evidence_items": 5
                }
            },
            "evidence": [
                {
                    "name": "Command and Scripting Interpreter",
                    "mitre_id": "T1059",
                    "source": "MITRE ATT&CK"
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
                "evidence_items": 5
            }
        }
    )

    agent = AttackCorrelationAgent()

    print("\n[1] Running Attack Correlation Agent...")

    state = agent.analyze(state)

    print("\n[2] Agent stage:")
    print(state.current_stage)

    print("\n[3] Correlation result:")

    print(state.correlation)

    print("\n[4] Correlations:")
    print(state.correlation.get("correlations"))

    print("\n[5] Attack chain:")
    print(state.correlation.get("attack_chain"))

    print("\n[6] Observed behaviors:")
    print(state.correlation.get("observed_behaviors"))

    print("\n[7] Retrieved techniques:")
    print(state.correlation.get("retrieved_techniques"))

    print("\n[8] Inferences:")
    print(state.correlation.get("inferences"))

    print("\n[9] Confidence:")
    print(state.correlation.get("confidence"))

    print("\n[10] Agent messages:")
    print(state.agent_messages)

    print("\n[11] Limitations:")
    print(state.limitations)

    print("\n" + "=" * 60)
    print("ATTACK CORRELATION AGENT TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()