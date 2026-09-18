from orchestration.state import AgentState
from orchestration.supervisor import Supervisor


def main():
    print("=" * 60)
    print("SUPERVISOR / ORCHESTRATOR TEST")
    print("=" * 60)

    state = AgentState(
        incident_id="INC-SUP-001",
        alert={
            "source": "test",
            "event": "Multiple failed SSH login attempts",
        },
    )

    supervisor = Supervisor()

    print("\n[1] Running complete multi-agent pipeline...")

    state = supervisor.analyze(state)

    print("\n[2] Final stage:")
    print(state.current_stage)

    print("\n[3] Detection:")
    print(state.detection)

    print("\n[4] Threat Intelligence:")
    print(state.threat_intelligence.get("status"))

    print("\n[5] Correlation:")
    print(state.correlation.get("confidence"))

    print("\n[6] Response:")
    print(state.response.get("response_priority"))

    print("\n[7] Explanation:")
    print(state.explanation.get("summary"))

    print("\n[8] Overall confidence:")
    print(state.confidence)

    print("\n[9] Agent messages:")
    for message in state.agent_messages:
        print(message)

    print("\n[10] Limitations:")
    print(state.limitations)

    print("\n" + "=" * 60)
    print("SUPERVISOR TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()