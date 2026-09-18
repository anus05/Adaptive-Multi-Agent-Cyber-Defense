from orchestration.state import AgentState
from orchestration.supervisor import Supervisor


def main():
    print("=" * 60)
    print("SUPERVISOR + ADAPTIVE FEEDBACK TEST")
    print("=" * 60)

    # ---------------------------------------------------------
    # 1. Create test incident
    # ---------------------------------------------------------

    state = AgentState(
        incident_id="INC-FEEDBACK-001",
        alert={
            "source": "test",
            "event": "Multiple failed SSH login attempts"
        }
    )

    supervisor = Supervisor()

    # ---------------------------------------------------------
    # 2. Run complete analysis
    # ---------------------------------------------------------

    print("\n[1] Running Supervisor pipeline...")

    state = supervisor.analyze(state)

    print("Pipeline stage:", state.current_stage)
    print("Overall confidence:", state.confidence)

    # ---------------------------------------------------------
    # 3. Check pending feedback
    # ---------------------------------------------------------

    print("\n[2] Checking pending feedback...")

    pending_feedback = state.feedback.get(
        "pending_feedback"
    )

    if not pending_feedback:
        raise RuntimeError(
            "Pending feedback was not created."
        )

    print(pending_feedback)

    # ---------------------------------------------------------
    # 4. Simulate actual outcome
    # ---------------------------------------------------------

    print("\n[3] Recording actual response outcome...")

    state = supervisor.record_outcome(
        state=state,
        outcome=(
            "Suspicious SSH activity was contained "
            "after the recommended monitoring action."
        ),
        success=True,
        analyst_feedback=(
            "The recommendation was useful "
            "for confirming the suspicious activity."
        ),
    )

    # ---------------------------------------------------------
    # 5. Check feedback result
    # ---------------------------------------------------------

    print("\n[4] Recorded feedback...")

    print(
        state.feedback.get(
            "outcome"
        )
    )

    # ---------------------------------------------------------
    # 6. Check adaptive policy
    # ---------------------------------------------------------

    print("\n[5] Updated adaptive policy...")

    policy = state.feedback.get(
        "adaptive_policy"
    )

    if not policy:
        raise RuntimeError(
            "Adaptive policy was not updated."
        )

    print(policy)

    # ---------------------------------------------------------
    # 7. Check adaptation status
    # ---------------------------------------------------------

    print("\n[6] Adaptation status...")

    adaptation_status = state.feedback.get(
        "adaptation_status"
    )

    print(adaptation_status)

    if adaptation_status != "policy_updated":
        raise RuntimeError(
            "Adaptive policy update was not confirmed."
        )

    # ---------------------------------------------------------
    # 8. Final checks
    # ---------------------------------------------------------

    print("\n[7] Final verification...")

    if state.current_stage != "feedback_recorded":
        raise RuntimeError(
            "State stage was not updated correctly."
        )

    if not state.feedback.get("outcome"):
        raise RuntimeError(
            "Feedback outcome is missing."
        )

    if not state.feedback.get("adaptive_policy"):
        raise RuntimeError(
            "Adaptive policy is missing."
        )

    print("Supervisor analysis: PASS")
    print("Feedback recording: PASS")
    print("Policy update: PASS")
    print("State update: PASS")

    print("\n" + "=" * 60)
    print("SUPERVISOR + ADAPTIVE FEEDBACK TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()