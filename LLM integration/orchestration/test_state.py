from orchestration.state import AgentState


def main():
    state = AgentState(
        incident_id="INC-001",
        alert={
            "source_ip": "192.168.1.10",
            "destination_ip": "10.0.0.5",
            "event_type": "suspicious_login",
        },
    )

    state.set_stage("detection")

    state.detection = {
        "label": "suspicious",
        "severity": "high",
    }

    state.add_message(
        agent="DetectionAgent",
        message="Suspicious login activity detected.",
        confidence=0.90,
    )

    state.set_stage("threat_intelligence")

    print("=" * 60)
    print("SHARED AGENT STATE TEST")
    print("=" * 60)

    print("\nIncident ID:")
    print(state.incident_id)

    print("\nCurrent Stage:")
    print(state.current_stage)

    print("\nDetection:")
    print(state.detection)

    print("\nAgent Messages:")
    print(state.agent_messages)

    print("\nComplete State:")
    print(state.to_dict())

    print("\nTEST PASSED")


if __name__ == "__main__":
    main()