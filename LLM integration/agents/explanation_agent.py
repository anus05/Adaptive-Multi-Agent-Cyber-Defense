import json
from typing import Any, Dict

from models.llm_client import ask_llm
from orchestration.state import AgentState


class ExplanationAgent:
    """
    Explanation Agent.

    Converts the outputs of the previous agents into
    a clear and traceable security explanation.

    It explicitly separates:
    - observed evidence
    - retrieved knowledge
    - correlation/inference
    - recommended response
    """

    def __init__(self):
        self.name = "ExplanationAgent"

    def _build_prompt(
        self,
        detection: Dict[str, Any],
        threat_intelligence: Dict[str, Any],
        correlation: Dict[str, Any],
        response: Dict[str, Any],
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

        response_json = json.dumps(
            response,
            indent=2,
            default=str
        )

        return f"""
You are a cybersecurity Explanation Agent.

Your task is to explain the complete security analysis
in a clear, concise and traceable way.

IMPORTANT RULES:

1. Do not invent facts.
2. Observed evidence comes only from the Detection Agent.
3. Retrieved knowledge comes from GraphRAG.
4. Correlation results are analysis/inference.
5. Recommended actions come from the Response Agent.
6. Never describe retrieved knowledge as observed evidence.
7. Clearly distinguish observation, retrieval, inference,
   and recommendation.
8. Mention important limitations.
9. Use simple professional cybersecurity language.
10. Return ONLY valid JSON.
11. Do not use markdown code fences.

DETECTION:
{detection_json}

THREAT INTELLIGENCE:
{threat_json}

ATTACK CORRELATION:
{correlation_json}

RESPONSE:
{response_json}

Return exactly this JSON structure:

{{
  "summary": "",
  "observed_evidence": [],
  "retrieved_knowledge": [],
  "correlation_explanation": "",
  "response_explanation": "",
  "inferences": [],
  "limitations": [],
  "confidence": 0.0
}}

Confidence must be a number between 0.0 and 1.0.
"""

    def analyze(self, state: AgentState) -> AgentState:

        state.set_stage("explanation")

        if not state.detection:
            state.explanation = {
                "status": "skipped",
                "reason": "Detection result is unavailable.",
                "confidence": 0.0,
                "limitations": [
                    "No detection result was available."
                ],
            }

            state.add_limitation(
                "Explanation Agent received no detection result."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Explanation skipped because "
                    "detection data was unavailable."
                ),
                confidence=0.0,
            )

            return state

        if not state.threat_intelligence:
            state.explanation = {
                "status": "skipped",
                "reason": (
                    "Threat intelligence result is unavailable."
                ),
                "confidence": 0.0,
                "limitations": [
                    "No threat intelligence was available."
                ],
            }

            state.add_limitation(
                "Explanation Agent received no threat intelligence."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Explanation skipped because "
                    "threat intelligence was unavailable."
                ),
                confidence=0.0,
            )

            return state

        if not state.correlation:
            state.explanation = {
                "status": "skipped",
                "reason": (
                    "Attack correlation result is unavailable."
                ),
                "confidence": 0.0,
                "limitations": [
                    "No attack correlation was available."
                ],
            }

            state.add_limitation(
                "Explanation Agent received no attack correlation."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Explanation skipped because "
                    "attack correlation was unavailable."
                ),
                confidence=0.0,
            )

            return state

        if not state.response:
            state.explanation = {
                "status": "skipped",
                "reason": (
                    "Response result is unavailable."
                ),
                "confidence": 0.0,
                "limitations": [
                    "No response recommendation was available."
                ],
            }

            state.add_limitation(
                "Explanation Agent received no response result."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Explanation skipped because "
                    "response data was unavailable."
                ),
                confidence=0.0,
            )

            return state

        prompt = self._build_prompt(
            state.detection,
            state.threat_intelligence,
            state.correlation,
            state.response,
        )

        raw_response = ask_llm(prompt)

        try:
            explanation_result = json.loads(raw_response)

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Explanation Agent received invalid JSON from Gemini."
            ) from exc

        self._validate_result(explanation_result)

        state.explanation = explanation_result

        confidence = float(
            explanation_result.get(
                "confidence",
                0.0
            )
        )

        for limitation in explanation_result.get(
            "limitations",
            []
        ):
            state.add_limitation(
                str(limitation)
            )

        state.add_message(
            agent=self.name,
            message=(
                "Security analysis explanation generated "
                "with evidence and inference separation."
            ),
            confidence=confidence,
        )

        state.set_stage(
            "explanation_complete"
        )

        return state

    @staticmethod
    def _validate_result(
        result: Dict[str, Any]
    ) -> None:

        required_fields = [
            "summary",
            "observed_evidence",
            "retrieved_knowledge",
            "correlation_explanation",
            "response_explanation",
            "inferences",
            "limitations",
            "confidence",
        ]

        missing_fields = [
            field
            for field in required_fields
            if field not in result
        ]

        if missing_fields:
            raise ValueError(
                "Explanation Agent response is missing fields: "
                f"{missing_fields}"
            )

        list_fields = [
            "observed_evidence",
            "retrieved_knowledge",
            "inferences",
            "limitations",
        ]

        for field in list_fields:
            if not isinstance(
                result[field],
                list
            ):
                raise ValueError(
                    f"{field} must be a list."
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