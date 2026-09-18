import json
import time
from pathlib import Path
from datetime import datetime, timezone

from orchestration.state import AgentState
from orchestration.supervisor import Supervisor


BASE_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = RESULTS_DIR / "agent_evaluation_results.json"


def run_evaluation():
    print("=" * 60)
    print("MEMBER 3 MULTI-AGENT SYSTEM EVALUATION")
    print("=" * 60)

    alert = {
        "event_type": "suspicious_login",
        "source_ip": "192.168.1.10",
        "destination_ip": "10.0.0.5",
        "failed_attempts": 8,
        "protocol": "SSH",
        "description": "Multiple failed SSH login attempts detected."
    }

    incident_id = "EVAL-001"

    state = AgentState(
        incident_id=incident_id,
        alert=alert
    )

    supervisor = Supervisor()

    start_time = time.perf_counter()

    try:
        final_state = supervisor.analyze(state)
        elapsed = time.perf_counter() - start_time

        result = {
            "evaluation_timestamp": datetime.now(
                timezone.utc
            ).isoformat(),

            "incident_id": incident_id,

            "pipeline_success": (
                final_state.current_stage == "pipeline_complete"
            ),

            "execution_time_seconds": round(elapsed, 3),

            "detection": {
                "status": bool(final_state.detection),
                "is_suspicious": final_state.detection.get(
                    "is_suspicious"
                ),
                "severity": final_state.detection.get(
                    "severity"
                ),
                "confidence": final_state.detection.get(
                    "confidence"
                ),
            },

            "threat_intelligence": {
                "status": final_state.threat_intelligence.get(
                    "status"
                ),
                "source": final_state.threat_intelligence.get(
                    "source"
                ),
                "retrieval_available": bool(
                    final_state.threat_intelligence.get(
                        "retrieved_context"
                    )
                ),
            },

            "correlation": {
                "status": bool(final_state.correlation),
                "confidence": final_state.correlation.get(
                    "confidence"
                ),
            },

            "response": {
                "status": bool(final_state.response),
                "priority": final_state.response.get(
                    "priority"
                ),
                "recommendation_only": final_state.response.get(
                    "recommendation_only"
                ),
            },

            "explanation": {
                "status": bool(final_state.explanation),
                "has_summary": bool(
                    final_state.explanation.get("summary")
                ),
            },

            "feedback": {
                "status": bool(final_state.feedback),
            },

            "overall_confidence": final_state.confidence,

            "agent_message_count": len(
                final_state.agent_messages
            ),

            "limitations": final_state.limitations,
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
        print("[RESULT]")
        print(f"Pipeline success: {result['pipeline_success']}")
        print(
            f"Execution time: "
            f"{result['execution_time_seconds']} seconds"
        )
        print(
            f"Detection suspicious: "
            f"{result['detection']['is_suspicious']}"
        )
        print(
            f"Detection confidence: "
            f"{result['detection']['confidence']}"
        )
        print(
            f"Threat intelligence: "
            f"{result['threat_intelligence']['status']}"
        )
        print(
            f"Correlation confidence: "
            f"{result['correlation']['confidence']}"
        )
        print(
            f"Response priority: "
            f"{result['response']['priority']}"
        )
        print(
            f"Recommendation only: "
            f"{result['response']['recommendation_only']}"
        )
        print(
            f"Explanation generated: "
            f"{result['explanation']['has_summary']}"
        )
        print(
            f"Agent messages: "
            f"{result['agent_message_count']}"
        )
        print(
            f"Overall confidence: "
            f"{result['overall_confidence']}"
        )

        print()
        print(f"Results saved to:")
        print(OUTPUT_FILE)

        if result["pipeline_success"]:
            print()
            print("=" * 60)
            print("EVALUATION PASSED")
            print("=" * 60)
        else:
            print()
            print("=" * 60)
            print("EVALUATION COMPLETED WITH PIPELINE FAILURE")
            print("=" * 60)

    except Exception as exc:
        elapsed = time.perf_counter() - start_time

        error_result = {
            "evaluation_timestamp": datetime.now(
                timezone.utc
            ).isoformat(),
            "incident_id": incident_id,
            "pipeline_success": False,
            "execution_time_seconds": round(elapsed, 3),
            "error": str(exc),
        }

        with open(
            OUTPUT_FILE,
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                error_result,
                file,
                indent=2,
                ensure_ascii=False
            )

        print()
        print("EVALUATION FAILED")
        print(f"Error: {exc}")
        print(f"Results saved to: {OUTPUT_FILE}")


if __name__ == "__main__":
    run_evaluation()