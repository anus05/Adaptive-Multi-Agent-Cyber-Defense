from typing import Any, Dict, List

from models.llm_client import ask_llm
from orchestration.state import AgentState


class ConflictHandler:
    """
    Detects and resolves disagreements between agent outputs.

    The handler:
    1. Checks detection confidence.
    2. Checks correlation confidence.
    3. Checks response priority.
    4. Identifies possible disagreement.
    5. Uses additional LLM reasoning only when needed.
    6. Keeps disagreements visible.
    """

    def __init__(self):
        self.name = "ConflictHandler"

    def detect_conflicts(
        self,
        state: AgentState,
    ) -> List[Dict[str, Any]]:
        """
        Identify disagreements between agent outputs.
        """

        conflicts = []

        detection_confidence = float(
            state.detection.get("confidence", 0.0)
        )

        correlation_confidence = float(
            state.correlation.get("confidence", 0.0)
        )

        response_priority = state.response.get(
            "response_priority",
            "unknown"
        )

        detection_severity = state.detection.get(
            "severity",
            "unknown"
        )

        # High-confidence detection but weak correlation
        if (
            detection_confidence >= 0.70
            and correlation_confidence < 0.50
        ):
            conflicts.append(
                {
                    "type": "confidence_disagreement",
                    "agents": [
                        "DetectionAgent",
                        "AttackCorrelationAgent",
                    ],
                    "description": (
                        "Detection confidence is high, "
                        "but correlation confidence is low."
                    ),
                    "detection_confidence": detection_confidence,
                    "correlation_confidence": correlation_confidence,
                }
            )

        # Detection severity vs response priority
        severity_levels = {
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }

        severity_value = severity_levels.get(
            str(detection_severity).lower(),
            0
        )

        priority_value = severity_levels.get(
            str(response_priority).lower(),
            0
        )

        if (
            severity_value >= 3
            and priority_value > 0
            and priority_value < severity_value
        ):
            conflicts.append(
                {
                    "type": "severity_priority_disagreement",
                    "agents": [
                        "DetectionAgent",
                        "ResponseAgent",
                    ],
                    "description": (
                        "Detection severity is higher than "
                        "the response priority."
                    ),
                    "detection_severity": detection_severity,
                    "response_priority": response_priority,
                }
            )

        return conflicts

    def resolve(
        self,
        state: AgentState,
    ) -> Dict[str, Any]:
        """
        Detect and resolve agent disagreements.
        """

        conflicts = self.detect_conflicts(state)

        # No conflict
        if not conflicts:
            confidence_values = [
                float(state.detection.get("confidence", 0.0)),
                float(state.correlation.get("confidence", 0.0)),
                float(state.response.get("confidence", 0.0)),
                float(state.explanation.get("confidence", 0.0)),
            ]

            valid_values = [
                value
                for value in confidence_values
                if 0.0 <= value <= 1.0
            ]

            final_confidence = (
                sum(valid_values) / len(valid_values)
                if valid_values
                else 0.0
            )

            return {
                "conflict_detected": False,
                "conflicts": [],
                "additional_reasoning_requested": False,
                "final_confidence": round(
                    final_confidence,
                    4
                ),
                "resolution": (
                    "No significant disagreement was detected "
                    "between the available agent outputs."
                ),
            }

        # Conflict exists.
        # Request additional reasoning from the LLM.
        prompt = self._build_resolution_prompt(
            state,
            conflicts,
        )

        raw_result = ask_llm(prompt)

        resolution = self._parse_resolution(
            raw_result
        )

        return {
            "conflict_detected": True,
            "conflicts": conflicts,
            "additional_reasoning_requested": True,
            "final_confidence": resolution[
                "final_confidence"
            ],
            "resolution": resolution[
                "resolution"
            ],
            "reasoning": resolution[
                "reasoning"
            ],
        }

    def _build_resolution_prompt(
        self,
        state: AgentState,
        conflicts: List[Dict[str, Any]],
    ) -> str:

        return f"""
You are the conflict-resolution component of a
cybersecurity multi-agent system.

Several security agents disagree.

Your task is to review the available evidence and
provide a cautious final assessment.

IMPORTANT RULES:

1. Do not invent facts.
2. Observed evidence comes only from DetectionAgent.
3. Retrieved knowledge comes from GraphRAG.
4. Correlation is an inference, not automatically a fact.
5. Response recommendations are recommendations only.
6. Do not hide the disagreement.
7. Prefer the conclusion supported by the available evidence.
8. If evidence is insufficient, explicitly say so.
9. Do not execute any security action.
10. Return ONLY valid JSON.
11. Do not use markdown code fences.

DETECTION:
{state.detection}

THREAT INTELLIGENCE:
{state.threat_intelligence}

CORRELATION:
{state.correlation}

RESPONSE:
{state.response}

EXPLANATION:
{state.explanation}

DETECTED CONFLICTS:
{conflicts}

Return exactly:

{{
    "final_confidence": 0.0,
    "resolution": "",
    "reasoning": ""
}}

final_confidence must be between 0.0 and 1.0.
"""

    @staticmethod
    def _parse_resolution(
        raw_result: str,
    ) -> Dict[str, Any]:

        import json

        try:
            result = json.loads(raw_result)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Conflict Handler received invalid JSON from Gemini."
            ) from exc

        required_fields = [
            "final_confidence",
            "resolution",
            "reasoning",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in result
        ]

        if missing_fields:
            raise ValueError(
                "Conflict Handler response is missing fields: "
                f"{missing_fields}"
            )

        confidence = result["final_confidence"]

        if not isinstance(
            confidence,
            (int, float)
        ):
            raise ValueError(
                "final_confidence must be numeric."
            )

        confidence = float(confidence)

        if not 0.0 <= confidence <= 1.0:
            raise ValueError(
                "final_confidence must be between 0.0 and 1.0."
            )

        if not isinstance(
            result["resolution"],
            str
        ):
            raise ValueError(
                "resolution must be a string."
            )

        if not isinstance(
            result["reasoning"],
            str
        ):
            raise ValueError(
                "reasoning must be a string."
            )

        return {
            "final_confidence": confidence,
            "resolution": result["resolution"],
            "reasoning": result["reasoning"],
        }