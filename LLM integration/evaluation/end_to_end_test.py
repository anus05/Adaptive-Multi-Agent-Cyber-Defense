import json
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parents[1]
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from orchestration.state import AgentState
from orchestration.supervisor import Supervisor

RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = RESULTS_DIR / "end_to_end_result.json"


def main():
    print("=" * 60)
    print("FINAL END-TO-END TEST")
    print("=" * 60)

    alert = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "failed_attempts": 8,
        "protocol": "SSH",
        "description": "Multiple failed SSH login attempts detected."
    }

    state = AgentState(
        incident_id="E2E-001",
        alert=alert
    )

    supervisor = Supervisor()

    start = time.perf_counter()

    try:
        final_state = supervisor.analyze(state)
        elapsed = time.perf_counter() - start

        result = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "incident_id": final_state.incident_id,
            "pipeline_stage": final_state.current_stage,
            "pipeline_complete": (
                final_state.current_stage == "pipeline_complete"
            ),
            "execution_time_seconds": round(elapsed, 3),

            "components": {
                "detection": bool(final_state.detection),
                "threat_intelligence": (
                    final_state.threat_intelligence.get("status")
                    == "received"
                ),
                "correlation": bool(final_state.correlation),
                "response": bool(final_state.response),
                "explanation": bool(final_state.explanation),
                "feedback": bool(final_state.feedback)
            },

            "overall_confidence": final_state.confidence,

            "agent_message_count": len(
                final_state.agent_messages
            ),

            "limitations": final_state.limitations
        }

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                result,
                file,
                indent=2,
                ensure_ascii=False
            )

        print()
        print("[FINAL RESULT]")
        print(f"Pipeline complete: {result['pipeline_complete']}")
        print(
            f"Execution time: "
            f"{result['execution_time_seconds']} seconds"
        )
        print(
            f"Detection: "
            f"{result['components']['detection']}"
        )
        print(
            f"Threat Intelligence: "
            f"{result['components']['threat_intelligence']}"
        )
        print(
            f"Correlation: "
            f"{result['components']['correlation']}"
        )
        print(
            f"Response: "
            f"{result['components']['response']}"
        )
        print(
            f"Explanation: "
            f"{result['components']['explanation']}"
        )
        print(
            f"Feedback: "
            f"{result['components']['feedback']}"
        )
        print(
            f"Overall confidence: "
            f"{result['overall_confidence']}"
        )
        print(
            f"Agent messages: "
            f"{result['agent_message_count']}"
        )

        print()
        print(f"Saved to:")
        print(OUTPUT_FILE)

        if result["pipeline_complete"]:
            print()
            print("=" * 60)
            print("END-TO-END TEST PASSED")
            print("=" * 60)
        else:
            print()
            print("END-TO-END TEST FAILED")

    except Exception as exc:
        print()
        print("END-TO-END TEST FAILED")
        print(f"Error: {exc}")


if __name__ == "__main__":
    main()