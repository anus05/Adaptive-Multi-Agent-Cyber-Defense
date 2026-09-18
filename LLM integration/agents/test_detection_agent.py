from agents.detection_agent import DetectionAgent
from orchestration.state import AgentState


def main():
    print("=" * 60)
    print("DETECTION AGENT TEST")
    print("=" * 60)

    state = AgentState(
        incident_id="INC-TEST-001",
        alert={
            "event_type": "suspicious_login",
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "failed_attempts": 8,
            "protocol": "SSH",
        },
    )

    agent = DetectionAgent()

    updated_state = agent.analyze(state)

    print("\nIncident ID:")
    print(updated_state.incident_id)

    print("\nDetection Result:")
    print(updated_state.detection)

    print("\nAgent Messages:")
    print(updated_state.agent_messages)

    print("\nCurrent Stage:")
    print(updated_state.current_stage)

    print("\nOverall Confidence:")
    print(updated_state.confidence)

    print("\nLimitations:")
    print(updated_state.limitations)

    print("\nTEST PASSED")


if __name__ == "__main__":
    main()