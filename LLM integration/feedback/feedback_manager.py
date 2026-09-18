import json
from pathlib import Path
from typing import Any, Dict, List


class FeedbackManager:
    """
    Adaptive feedback manager.

    Stores response outcomes and learns a simple
    policy for each individual response strategy.

    IMPORTANT:
    This component does not retrain the LLM.
    It only updates a decision policy from previous outcomes.
    """

    def __init__(
        self,
        storage_path: str = "feedback/feedback_history.json"
    ):
        self.name = "FeedbackManager"
        self.storage_path = Path(storage_path)

        self.storage_path.parent.mkdir(
            parents=True,
            exist_ok=True
        )

        self.history: List[Dict[str, Any]] = []
        self.policy: Dict[str, Dict[str, Any]] = {}

        self._load()

    # ---------------------------------------------------------
    # LOAD
    # ---------------------------------------------------------

    def _load(self) -> None:

        if not self.storage_path.exists():
            self.history = []
            self.policy = {}
            return

        try:
            with self.storage_path.open(
                "r",
                encoding="utf-8"
            ) as file:
                data = json.load(file)

        except (json.JSONDecodeError, OSError):
            self.history = []
            self.policy = {}
            return

        if not isinstance(data, dict):
            self.history = []
            self.policy = {}
            return

        history = data.get("history", [])
        policy = data.get("policy", {})

        self.history = (
            history
            if isinstance(history, list)
            else []
        )

        self.policy = (
            policy
            if isinstance(policy, dict)
            else {}
        )

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    def _save(self) -> None:

        data = {
            "history": self.history,
            "policy": self.policy
        }

        with self.storage_path.open(
            "w",
            encoding="utf-8"
        ) as file:
            json.dump(
                data,
                file,
                indent=4
            )

    # ---------------------------------------------------------
    # VALIDATION
    # ---------------------------------------------------------

    @staticmethod
    def _validate_feedback(
        incident_id: str,
        recommendation: str,
        action: str,
        outcome: str,
        success: bool,
        analyst_feedback: str,
        confidence: float,
    ) -> None:

        if not isinstance(
            incident_id,
            str
        ) or not incident_id.strip():
            raise ValueError(
                "incident_id must be a non-empty string."
            )

        if not isinstance(
            recommendation,
            str
        ) or not recommendation.strip():
            raise ValueError(
                "recommendation must be a non-empty string."
            )

        if not isinstance(
            action,
            str
        ) or not action.strip():
            raise ValueError(
                "action must be a non-empty string."
            )

        if not isinstance(
            outcome,
            str
        ) or not outcome.strip():
            raise ValueError(
                "outcome must be a non-empty string."
            )

        if not isinstance(
            success,
            bool
        ):
            raise TypeError(
                "success must be True or False."
            )

        if not isinstance(
            analyst_feedback,
            str
        ):
            raise TypeError(
                "analyst_feedback must be a string."
            )

        if not isinstance(
            confidence,
            (int, float)
        ):
            raise TypeError(
                "confidence must be numeric."
            )

        confidence = float(confidence)

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "confidence must be between 0.0 and 1.0."
            )

    # ---------------------------------------------------------
    # RECORD FEEDBACK
    # ---------------------------------------------------------

    def record_feedback(
        self,
        incident_id: str,
        recommendation: str,
        action: str,
        outcome: str,
        success: bool,
        analyst_feedback: str = "",
        confidence: float = 0.0,
    ) -> Dict[str, Any]:

        self._validate_feedback(
            incident_id=incident_id,
            recommendation=recommendation,
            action=action,
            outcome=outcome,
            success=success,
            analyst_feedback=analyst_feedback,
            confidence=confidence,
        )

        record = {
            "incident_id": incident_id.strip(),
            "recommendation": recommendation.strip(),
            "action": action.strip(),
            "outcome": outcome.strip(),
            "success": success,
            "analyst_feedback": analyst_feedback.strip(),
            "confidence": round(
                float(confidence),
                4
            ),
        }

        self.history.append(record)

        self._update_policy(
            recommendation=recommendation.strip(),
            success=success
        )

        self._save()

        return record

    # ---------------------------------------------------------
    # UPDATE POLICY
    # ---------------------------------------------------------

    def _update_policy(
        self,
        recommendation: str,
        success: bool
    ) -> None:

        if recommendation not in self.policy:

            self.policy[recommendation] = {
                "success_count": 0,
                "failure_count": 0,
                "total_count": 0,
                "success_rate": 0.0,
                "priority_adjustment": 0
            }

        entry = self.policy[recommendation]

        if success:
            entry["success_count"] += 1
        else:
            entry["failure_count"] += 1

        entry["total_count"] += 1

        total_count = entry["total_count"]
        success_count = entry["success_count"]

        entry["success_rate"] = round(
            success_count / total_count,
            4
        )

        # Simple adaptive policy.
        #
        # >= 70% success:
        #     increase priority
        #
        # <= 30% success:
        #     decrease priority
        #
        # otherwise:
        #     keep priority unchanged

        if entry["success_rate"] >= 0.70:

            entry["priority_adjustment"] = 1

        elif entry["success_rate"] <= 0.30:

            entry["priority_adjustment"] = -1

        else:

            entry["priority_adjustment"] = 0

    # ---------------------------------------------------------
    # GET ONE POLICY
    # ---------------------------------------------------------

    def get_policy(
        self,
        recommendation: str
    ) -> Dict[str, Any]:

        recommendation = recommendation.strip()

        if recommendation not in self.policy:

            return {
                "recommendation": recommendation,
                "success_count": 0,
                "failure_count": 0,
                "total_count": 0,
                "success_rate": 0.0,
                "priority_adjustment": 0,
                "history_available": False
            }

        result = dict(
            self.policy[recommendation]
        )

        result["recommendation"] = recommendation
        result["history_available"] = True

        return result

    # ---------------------------------------------------------
    # GET ALL POLICIES
    # ---------------------------------------------------------

    def get_all_policy(
        self
    ) -> Dict[str, Dict[str, Any]]:

        return {
            key: dict(value)
            for key, value in self.policy.items()
        }

    # ---------------------------------------------------------
    # GET HISTORY
    # ---------------------------------------------------------

    def get_history(
        self
    ) -> List[Dict[str, Any]]:

        return list(self.history)