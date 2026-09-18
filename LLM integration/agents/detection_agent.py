import json
from typing import Any, Dict

from models.llm_client import ask_llm
from orchestration.state import AgentState


class DetectionAgent:
    """
    Detection Agent for Member 3.

    Responsibilities:
    - Interpret the ML/security alert
    - Summarize suspicious behavior
    - Extract useful entities
    - Produce structured reasoning
    - Update the shared AgentState

    This agent does NOT perform the actual ML detection.
    """

    def __init__(self):
        self.name = "DetectionAgent"

    def _build_prompt(self, alert: Dict[str, Any]) -> str:
        """
        Build an evidence-grounded prompt for Gemini.
        """

        alert_json = json.dumps(alert, indent=2, default=str)

        return f"""
You are a cybersecurity Detection Agent.

Your job is to interpret the security alert provided below.

IMPORTANT RULES:
1. Do not invent facts.
2. Use only information present in the alert.
3. Clearly separate observed evidence from inference.
4. Do not claim a MITRE ATT&CK technique was observed unless
   the alert itself provides evidence for it.
5. If information is insufficient, say so.
6. Return ONLY valid JSON.
7. Do not use markdown code fences.

Security alert:
{alert_json}

Return exactly this JSON structure:

{{
  "is_suspicious": true,
  "severity": "low|medium|high|critical|unknown",
  "behavior_summary": "short description",
  "entities": [],
  "observed_evidence": [],
  "inference": [],
  "reasoning": "short explanation",
  "confidence": 0.0,
  "limitations": []
}}

The confidence must be a number between 0.0 and 1.0.
"""

    def analyze(
        self,
        state: AgentState,
    ) -> AgentState:
        """
        Analyze the alert and update the shared AgentState.
        """

        state.set_stage("detection")

        if not state.alert:
            state.add_limitation(
                "Detection Agent received an empty security alert."
            )

            state.detection = {
                "is_suspicious": False,
                "severity": "unknown",
                "behavior_summary": "",
                "entities": [],
                "observed_evidence": [],
                "inference": [],
                "reasoning": "No alert data was provided.",
                "confidence": 0.0,
                "limitations": [
                    "No security alert was provided."
                ],
            }

            state.add_message(
                agent=self.name,
                message="No alert data was available for analysis.",
                confidence=0.0,
            )

            return state

        prompt = self._build_prompt(state.alert)

        raw_response = ask_llm(prompt)

        try:
            detection_result = json.loads(raw_response)
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Detection Agent received invalid JSON from Gemini."
            ) from exc

        self._validate_result(detection_result)

        state.detection = detection_result

        confidence = detection_result.get("confidence", 0.0)

        state.confidence = confidence

        for limitation in detection_result.get("limitations", []):
            state.add_limitation(str(limitation))

        state.add_message(
            agent=self.name,
            message="Security alert interpreted and structured.",
            confidence=confidence,
        )

        state.set_stage("detection_complete")

        return state

    @staticmethod
    def _validate_result(result: Dict[str, Any]) -> None:
        """
        Validate the basic structure returned by the LLM.
        """

        required_fields = [
            "is_suspicious",
            "severity",
            "behavior_summary",
            "entities",
            "observed_evidence",
            "inference",
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
                f"Detection Agent response is missing fields: "
                f"{missing_fields}"
            )

        confidence = result["confidence"]

        if not isinstance(confidence, (int, float)):
            raise ValueError(
                "Detection Agent confidence must be numeric."
            )

        if not 0.0 <= float(confidence) <= 1.0:
            raise ValueError(
                "Detection Agent confidence must be between 0.0 and 1.0."
            )

        if not isinstance(result["entities"], list):
            raise ValueError(
                "Detection Agent entities must be a list."
            )

        if not isinstance(result["observed_evidence"], list):
            raise ValueError(
                "Detection Agent observed_evidence must be a list."
            )

        if not isinstance(result["inference"], list):
            raise ValueError(
                "Detection Agent inference must be a list."
            )

        if not isinstance(result["limitations"], list):
            raise ValueError(
                "Detection Agent limitations must be a list."
            )