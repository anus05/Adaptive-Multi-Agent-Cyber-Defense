import json
from typing import Any, Dict

from models.llm_client import ask_llm
from orchestration.state import AgentState


class ResponseAgent:
    """
    Response Agent.

    Generates defensive recommendations based on:
    - Detection results
    - Threat intelligence
    - Attack correlation

    IMPORTANT:
    This agent only recommends actions.
    It does not execute system/network changes.
    """

    def __init__(self):
        self.name = "ResponseAgent"

    def _build_prompt(
        self,
        detection: Dict[str, Any],
        threat_intelligence: Dict[str, Any],
        correlation: Dict[str, Any],
    ) -> str:

        detection_json = json.dumps(
            detection,
            indent=2,
            default=str
        )

        threat_json = json.dumps(
            threat_intelligence,
            indent=2,
            default=str
        )

        correlation_json = json.dumps(
            correlation,
            indent=2,
            default=str
        )

        return f"""
You are a cybersecurity Response Agent.

Your task is to recommend defensive actions based only on
the provided security analysis.

IMPORTANT RULES:

1. Do not invent facts.
2. Use the Detection Agent output as observed evidence.
3. Treat GraphRAG information as retrieved knowledge.
4. Treat correlation results as analysis, not confirmed facts.
5. Recommend defensive actions only.
6. Do NOT execute or claim to execute any action.
7. Do NOT recommend destructive actions such as deleting
   systems, destroying data, or disabling critical services.
8. Prefer safe, reversible and practical recommendations.
9. Clearly explain why each recommendation is suggested.
10. If evidence is insufficient, say so.
11. Return ONLY valid JSON.
12. Do not use markdown code fences.

DETECTION RESULT:
{detection_json}

THREAT INTELLIGENCE:
{threat_json}

ATTACK CORRELATION:
{correlation_json}

Return exactly this JSON structure:

{{
  "response_priority": "low|medium|high|critical",
  "recommended_actions": [
    {{
      "action": "",
      "reason": "",
      "priority": "low|medium|high|critical",
      "type": "investigation|containment|credential_security|monitoring|hardening",
      "reversible": true
    }}
  ],
  "immediate_actions": [],
  "follow_up_actions": [],
  "human_approval_required": true,
  "execution_status": "recommendation_only",
  "reasoning": "",
  "confidence": 0.0,
  "limitations": []
}}

The confidence must be a number between 0.0 and 1.0.

The field "execution_status" must always be:
"recommendation_only"

The field "human_approval_required" must always be:
true
"""

    def analyze(self, state: AgentState) -> AgentState:

        state.set_stage("response")

        if not state.detection:
            state.response = {
                "status": "skipped",
                "reason": "Detection result is unavailable.",
                "recommended_actions": [],
                "execution_status": "recommendation_only",
                "human_approval_required": True,
                "confidence": 0.0,
                "limitations": [
                    "No detection result was available."
                ],
            }

            state.add_limitation(
                "Response Agent received no detection result."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Response recommendation skipped because "
                    "detection data was unavailable."
                ),
                confidence=0.0,
            )

            return state

        if not state.threat_intelligence:
            state.response = {
                "status": "skipped",
                "reason": (
                    "Threat intelligence result is unavailable."
                ),
                "recommended_actions": [],
                "execution_status": "recommendation_only",
                "human_approval_required": True,
                "confidence": 0.0,
                "limitations": [
                    "No threat intelligence was available."
                ],
            }

            state.add_limitation(
                "Response Agent received no threat intelligence."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Response recommendation skipped because "
                    "threat intelligence was unavailable."
                ),
                confidence=0.0,
            )

            return state

        if not state.correlation:
            state.response = {
                "status": "skipped",
                "reason": (
                    "Attack correlation result is unavailable."
                ),
                "recommended_actions": [],
                "execution_status": "recommendation_only",
                "human_approval_required": True,
                "confidence": 0.0,
                "limitations": [
                    "No attack correlation was available."
                ],
            }

            state.add_limitation(
                "Response Agent received no attack correlation."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Response recommendation skipped because "
                    "attack correlation was unavailable."
                ),
                confidence=0.0,
            )

            return state

        prompt = self._build_prompt(
            state.detection,
            state.threat_intelligence,
            state.correlation,
        )

        raw_response = ask_llm(prompt)

        try:
            response_result = json.loads(raw_response)

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Response Agent received invalid JSON from Gemini."
            ) from exc

        self._validate_result(response_result)

        state.response = response_result

        confidence = float(
            response_result.get("confidence", 0.0)
        )

        for limitation in response_result.get(
            "limitations",
            []
        ):
            state.add_limitation(str(limitation))

        state.add_message(
            agent=self.name,
            message=(
                "Defensive response recommendations generated. "
                "No actions were automatically executed."
            ),
            confidence=confidence,
        )

        state.set_stage("response_complete")

        return state

    @staticmethod
    def _validate_result(result: Dict[str, Any]) -> None:

        required_fields = [
            "response_priority",
            "recommended_actions",
            "immediate_actions",
            "follow_up_actions",
            "human_approval_required",
            "execution_status",
            "reasoning",
            "confidence",
            "limitations",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in result
        ]

        if missing_fields:
            raise ValueError(
                "Response Agent response is missing fields: "
                f"{missing_fields}"
            )

        valid_priorities = {
            "low",
            "medium",
            "high",
            "critical",
        }

        if result["response_priority"] not in valid_priorities:
            raise ValueError(
                "Response priority must be low, medium, "
                "high, or critical."
            )

        if not isinstance(
            result["recommended_actions"],
            list
        ):
            raise ValueError(
                "recommended_actions must be a list."
            )

        if not isinstance(
            result["immediate_actions"],
            list
        ):
            raise ValueError(
                "immediate_actions must be a list."
            )

        if not isinstance(
            result["follow_up_actions"],
            list
        ):
            raise ValueError(
                "follow_up_actions must be a list."
            )

        if result["human_approval_required"] is not True:
            raise ValueError(
                "human_approval_required must be true."
            )

        if result["execution_status"] != "recommendation_only":
            raise ValueError(
                "execution_status must be "
                "'recommendation_only'."
            )

        if not isinstance(
            result["limitations"],
            list
        ):
            raise ValueError(
                "limitations must be a list."
            )

        confidence = result["confidence"]

        if not isinstance(
            confidence,
            (int, float)
        ):
            raise ValueError(
                "confidence must be numeric."
            )

        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError(
                "confidence must be between 0.0 and 1.0."
            )

        for index, action in enumerate(
            result["recommended_actions"]
        ):

            if not isinstance(action, dict):
                raise ValueError(
                    f"Recommended action {index} must be an object."
                )

            required_action_fields = [
                "action",
                "reason",
                "priority",
                "type",
                "reversible",
            ]

            missing_action_fields = [
                field
                for field in required_action_fields
                if field not in action
            ]

            if missing_action_fields:
                raise ValueError(
                    f"Recommended action {index} is missing fields: "
                    f"{missing_action_fields}"
                )

            if action["priority"] not in valid_priorities:
                raise ValueError(
                    f"Recommended action {index} has an invalid priority."
                )

            valid_types = {
                "investigation",
                "containment",
                "credential_security",
                "monitoring",
                "hardening",
            }

            if action["type"] not in valid_types:
                raise ValueError(
                    f"Recommended action {index} has an invalid type."
                )

            if not isinstance(
                action["reversible"],
                bool
            ):
                raise ValueError(
                    f"Recommended action {index} reversible "
                    "must be boolean."
                )