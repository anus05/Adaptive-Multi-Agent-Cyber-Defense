from orchestration.state import AgentState
from agents.threat_intelligence_agent import ThreatIntelligenceAgent


def main():
    print("=" * 60)
    print("THREAT INTELLIGENCE AGENT TEST")
    print("=" * 60)

    state = AgentState(
        incident_id="INC-TI-001",
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
            "reasoning": "Repeated failed SSH authentication attempts may indicate suspicious activity.",
            "confidence": 0.90,
            "limitations": [],
        },
    )

    agent = ThreatIntelligenceAgent()

    print("\n[1] Running Threat Intelligence Agent...")
    state = agent.analyze(state)

    print("\n[2] Agent stage:")
    print(state.current_stage)

    print("\n[3] Threat intelligence status:")
    print(state.threat_intelligence.get("status"))

    print("\n[4] GraphRAG source:")
    print(state.threat_intelligence.get("source"))

    print("\n[5] Retrieved context:")
    print(state.threat_intelligence.get("retrieved_context"))

    print("\n[6] Agent messages:")
    print(state.agent_messages)

    print("\n" + "=" * 60)
    print("THREAT INTELLIGENCE AGENT TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()