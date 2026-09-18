import json
from typing import Any, Dict, List

from models.llm_client import ask_llm
from orchestration.state import AgentState


class AttackCorrelationAgent:
    """
    Correlates observed detection evidence with
    retrieved GraphRAG threat intelligence.

    Important:
    Retrieved knowledge is not automatically treated
    as observed attack evidence.
    """

    def __init__(self):
        self.name = "AttackCorrelationAgent"

    def _build_prompt(
        self,
        detection: Dict[str, Any],
        threat_intelligence: Dict[str, Any],
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

        return f"""
You are a cybersecurity Attack Correlation Agent.

Your task is to correlate observed security evidence
with retrieved cybersecurity threat intelligence.

IMPORTANT RULES:

1. Do not invent facts.
2. Observed evidence comes only from the Detection Agent.
3. Retrieved knowledge comes from the GraphRAG system.
4. A retrieved MITRE ATT&CK technique must NOT be described
   as observed unless the detection evidence supports it.
5. Clearly distinguish:
   - observed evidence
   - retrieved knowledge
   - possible correlation
   - inference
6. If there is insufficient evidence for a correlation,
   say so.
7. Do not make destructive response decisions.
8. Return ONLY valid JSON.
9. Do not use markdown code fences.

DETECTION RESULT:
{detection_json}

GRAPH-RAG THREAT INTELLIGENCE:
{threat_json}

Return exactly this JSON structure:

{{
  "correlations": [
    {{
      "observed_evidence": "",
      "retrieved_entity": "",
      "retrieved_mitre_id": "",
      "relationship": "",
      "basis": "",
      "confidence": 0.0
    }}
  ],
  "attack_chain": [],
  "observed_behaviors": [],
  "retrieved_techniques": [],
  "inferences": [],
  "reasoning": "",
  "confidence": 0.0,
  "limitations": []
}}

Confidence must be between 0.0 and 1.0.
"""

    def analyze(self, state: AgentState) -> AgentState:

        state.set_stage("attack_correlation")

        if not state.detection:
            state.correlation = {
                "status": "skipped",
                "reason": "Detection result is unavailable.",
            }

            state.add_limitation(
                "Attack Correlation Agent received no detection result."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Attack correlation skipped because "
                    "detection data was unavailable."
                ),
                confidence=0.0,
            )

            return state

        if not state.threat_intelligence:
            state.correlation = {
                "status": "skipped",
                "reason": (
                    "Threat intelligence result is unavailable."
                ),
            }

            state.add_limitation(
                "Attack Correlation Agent received no threat intelligence."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Attack correlation skipped because "
                    "threat intelligence was unavailable."
                ),
                confidence=0.0,
            )

            return state

        prompt = self._build_prompt(
            state.detection,
            state.threat_intelligence,
        )

        raw_response = ask_llm(prompt)

        try:
            correlation_result = json.loads(raw_response)

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "Attack Correlation Agent received invalid JSON from Gemini."
            ) from exc

        self._validate_result(correlation_result)

        state.correlation = correlation_result

        confidence = float(
            correlation_result.get("confidence", 0.0)
        )

        for limitation in correlation_result.get(
            "limitations",
            []
        ):
            state.add_limitation(str(limitation))

        state.add_message(
            agent=self.name,
            message=(
                "Detection evidence was correlated with "
                "retrieved threat intelligence."
            ),
            confidence=confidence,
        )

        state.set_stage("attack_correlation_complete")

        return state

    @staticmethod
    def _validate_result(result: Dict[str, Any]) -> None:

        required_fields = [
            "correlations",
            "attack_chain",
            "observed_behaviors",
            "retrieved_techniques",
            "inferences",
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
                "Attack Correlation Agent response is missing fields: "
                f"{missing_fields}"
            )

        if not isinstance(
            result["correlations"],
            list
        ):
            raise ValueError(
                "correlations must be a list."
            )

        if not isinstance(
            result["attack_chain"],
            list
        ):
            raise ValueError(
                "attack_chain must be a list."
            )

        if not isinstance(
            result["observed_behaviors"],
            list
        ):
            raise ValueError(
                "observed_behaviors must be a list."
            )

        if not isinstance(
            result["retrieved_techniques"],
            list
        ):
            raise ValueError(
                "retrieved_techniques must be a list."
            )

        if not isinstance(
            result["inferences"],
            list
        ):
            raise ValueError(
                "inferences must be a list."
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