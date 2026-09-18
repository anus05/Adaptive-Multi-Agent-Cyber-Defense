import json
import time
from pathlib import Path
from datetime import datetime, timezone

from orchestration.state import AgentState
from agents.detection_agent import DetectionAgent
from orchestration.supervisor import Supervisor


BASE_DIR = Path(__file__).resolve().parents[1]
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

OUTPUT_FILE = RESULTS_DIR / "baseline_comparison_results.json"


ALERT = {
    "event_type": "suspicious_login",
    "source_ip": "192.168.1.10",
    "destination_ip": "10.0.0.5",
    "failed_attempts": 8,
    "protocol": "SSH",
    "description": "Multiple failed SSH login attempts detected."
}


def run_detection_baseline():
    state = AgentState(
        incident_id="BASELINE-001",
        alert=ALERT
    )

    agent = DetectionAgent()

    start = time.perf_counter()
    state = agent.analyze(state)
    elapsed = time.perf_counter() - start

    return {
        "name": "Detection Agent Only",
        "execution_time_seconds": round(elapsed, 3),
        "completed": bool(state.detection),
        "is_suspicious": state.detection.get("is_suspicious"),
        "confidence": state.detection.get("confidence")
    }


def run_proposed_system():
    state = AgentState(
        incident_id="PROPOSED-001",
        alert=ALERT
    )

    supervisor = Supervisor()

    start = time.perf_counter()
    state = supervisor.analyze(state)
    elapsed = time.perf_counter() - start

    return {
        "name": "Proposed Multi-Agent Framework",
        "execution_time_seconds": round(elapsed, 3),
        "completed": state.current_stage == "pipeline_complete",
        "overall_confidence": state.confidence,
        "agent_message_count": len(state.agent_messages)
    }


def main():
    print("=" * 60)
    print("BASELINE COMPARISON")
    print("=" * 60)

    print("\n[1] Running Detection Agent baseline...")
    baseline = run_detection_baseline()

    print("[2] Running proposed multi-agent framework...")
    proposed = run_proposed_system()

    result = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "evaluation_note": (
            "Comparison uses measured execution time and pipeline "
            "completion. No accuracy or F1 score is reported because "
            "this evaluation does not contain ground-truth labels."
        ),
        "baseline": baseline,
        "proposed_system": proposed
    }

    with open(OUTPUT_FILE, "w", encoding="utf-8") as file:
        json.dump(
            result,
            file,
            indent=2,
            ensure_ascii=False
        )

    print("\n" + "=" * 60)
    print("RESULTS")
    print("=" * 60)

    print(
        f"\nBaseline time: "
        f"{baseline['execution_time_seconds']} seconds"
    )

    print(
        f"Proposed system time: "
        f"{proposed['execution_time_seconds']} seconds"
    )

    print(
        f"Baseline completed: "
        f"{baseline['completed']}"
    )

    print(
        f"Proposed system completed: "
        f"{proposed['completed']}"
    )

    print(
        f"Proposed overall confidence: "
        f"{proposed['overall_confidence']}"
    )

    print(
        f"Agent messages: "
        f"{proposed['agent_message_count']}"
    )

    print(f"\nSaved to:")
    print(OUTPUT_FILE)

    if baseline["completed"] and proposed["completed"]:
        print("\nBASELINE COMPARISON PASSED")
    else:
        print("\nBASELINE COMPARISON COMPLETED WITH FAILURE")


if __name__ == "__main__":
    main()