from feedback.feedback_manager import FeedbackManager


def main():

    print("=" * 60)
    print("RESPONSE-SPECIFIC ADAPTIVE POLICY TEST")
    print("=" * 60)

    # Use a fresh test file.
    test_file = "feedback/test_response_policy.json"

    manager = FeedbackManager(
        storage_path=test_file
    )

    # ---------------------------------------------------------
    # 1. Successful response
    # ---------------------------------------------------------

    print("\n[1] Recording successful response...")

    manager.record_feedback(
        incident_id="INC-001",
        recommendation="Increase monitoring",
        action="Increase monitoring on SSH service",
        outcome="Suspicious activity was confirmed.",
        success=True,
        analyst_feedback="Useful recommendation.",
        confidence=0.90,
    )

    # ---------------------------------------------------------
    # 2. Another successful response
    # ---------------------------------------------------------

    print("\n[2] Recording second successful response...")

    manager.record_feedback(
        incident_id="INC-002",
        recommendation="Increase monitoring",
        action="Increase monitoring on SSH service",
        outcome="No further suspicious activity observed.",
        success=True,
        analyst_feedback="Monitoring was effective.",
        confidence=0.85,
    )

    # ---------------------------------------------------------
    # 3. Record a different response
    # ---------------------------------------------------------

    print("\n[3] Recording failed response strategy...")

    manager.record_feedback(
        incident_id="INC-003",
        recommendation="Block IP",
        action="Block suspicious source IP",
        outcome="Suspicious activity continued.",
        success=False,
        analyst_feedback="Blocking this IP did not stop the activity.",
        confidence=0.80,
    )

    # ---------------------------------------------------------
    # 4. Check monitoring policy
    # ---------------------------------------------------------

    print("\n[4] Increase monitoring policy:")

    monitoring_policy = manager.get_policy(
        "Increase monitoring"
    )

    print(monitoring_policy)

    # ---------------------------------------------------------
    # 5. Check block IP policy
    # ---------------------------------------------------------

    print("\n[5] Block IP policy:")

    block_policy = manager.get_policy(
        "Block IP"
    )

    print(block_policy)

    # ---------------------------------------------------------
    # 6. Verify separate policies
    # ---------------------------------------------------------

    print("\n[6] Checking response-specific learning...")

    all_policy = manager.get_all_policy()

    print("Number of learned response strategies:")

    print(len(all_policy))

    if "Increase monitoring" not in all_policy:
        raise RuntimeError(
            "Increase monitoring policy was not stored."
        )

    if "Block IP" not in all_policy:
        raise RuntimeError(
            "Block IP policy was not stored."
        )

    if (
        all_policy["Increase monitoring"]["success_rate"]
        != 1.0
    ):
        raise RuntimeError(
            "Increase monitoring success rate is incorrect."
        )

    if (
        all_policy["Block IP"]["success_rate"]
        != 0.0
    ):
        raise RuntimeError(
            "Block IP success rate is incorrect."
        )

    # ---------------------------------------------------------
    # 7. Check adaptive adjustments
    # ---------------------------------------------------------

    print("\n[7] Checking priority adjustments...")

    print(
        "Increase monitoring adjustment:",
        all_policy["Increase monitoring"][
            "priority_adjustment"
        ]
    )

    print(
        "Block IP adjustment:",
        all_policy["Block IP"][
            "priority_adjustment"
        ]
    )

    if (
        all_policy["Increase monitoring"][
            "priority_adjustment"
        ] != 1
    ):
        raise RuntimeError(
            "Successful response did not receive +1 adjustment."
        )

    if (
        all_policy["Block IP"][
            "priority_adjustment"
        ] != -1
    ):
        raise RuntimeError(
            "Failed response did not receive -1 adjustment."
        )

    # ---------------------------------------------------------
    # 8. Check history
    # ---------------------------------------------------------

    print("\n[8] Checking feedback history...")

    history = manager.get_history()

    print(
        "Total records:",
        len(history)
    )

    if len(history) != 3:
        raise RuntimeError(
            "Expected exactly 3 feedback records."
        )

    # ---------------------------------------------------------
    # Final
    # ---------------------------------------------------------

    print("\n" + "=" * 60)
    print("RESPONSE-SPECIFIC ADAPTIVE POLICY TEST PASSED")
    print("=" * 60)


if __name__ == "__main__":
    main()