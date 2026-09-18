from orchestration.state import AgentState
from orchestration.conflict_handler import ConflictHandler


def main():
    print("=" * 60)
    print("CONFLICT HANDLER TEST")
    print("=" * 60)

    state = AgentState(
        incident_id="INC-CONFLICT-001",

        detection={
            "is_suspicious": True,
            "severity": "high",
            "behavior_summary": "Multiple failed SSH login attempts",
            "observed_evidence": [
                "Multiple failed SSH login attempts"
            ],
            "confidence": 0.90,
        },

        threat_intelligence={
            "status": "received",
            "source": "Member 2 GraphRAG API",
            "evidence": [
                {
                    "name": "Command and Scripting Interpreter",
                    "mitre_id": "T1059",
                    "source": "MITRE ATT&CK",
                }
            ],
        },

        correlation={
            "correlations": [],
            "retrieved_techniques": [
                "Command and Scripting Interpreter (T1059)"
            ],
            "confidence": 0.20,
            "limitations": [
                "Insufficient direct correlation."
            ],
        },

        response={
            "response_priority": "medium",
            "recommended_actions": [],
            "confidence": 0.60,
        },

        explanation={
            "summary": (
                "The observed SSH activity is suspicious, "
                "but the retrieved technique is not directly "
                "supported by the observed evidence."
            ),
            "confidence": 0.60,
        },
    )

    handler = ConflictHandler()

    print("\n[1] Detecting conflicts...")

    conflicts = handler.detect_conflicts(state)

    print("\n[2] Conflict detected:")
    print(bool(conflicts))

    print("\n[3] Conflicts:")
    for conflict in conflicts:
        print(conflict)

    if not conflicts:
        print("\nERROR: Expected a conflict but none was detected.")
        return

    print("\n[4] Resolving conflict...")

    result = handler.resolve(state)

    print("\n[5] Conflict detected:")
    print(result.get("conflict_detected"))

    print("\n[6] Additional reasoning requested:")
    print(result.get("additional_reasoning_requested"))

    print("\n[7] Final confidence:")
    print(result.get("final_confidence"))

    print("\n[8] Resolution:")
    print(result.get("resolution"))

    print("\n[9] Reasoning:")
    print(result.get("reasoning"))

    print("\n" + "=" * 60)
    print("CONFLICT HANDLER TEST COMPLETED")
    print("=" * 60)


if __name__ == "__main__":
    main()