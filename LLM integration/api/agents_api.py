from typing import Any, Dict, List

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from orchestration.state import AgentState
from orchestration.supervisor import Supervisor


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="Adaptive Multi-Agent Cyber Defense API",
    description=(
        "Member 3 API for multi-agent cybersecurity analysis "
        "using LLM reasoning, GraphRAG context, conflict handling, "
        "and adaptive feedback."
    ),
    version="1.0.0",
)


# ============================================================
# REQUEST MODEL
# ============================================================

class AnalyzeRequest(BaseModel):
    incident_id: str = Field(
        ...,
        min_length=1,
        description="Unique security incident identifier."
    )

    alert: Dict[str, Any] = Field(
        ...,
        description="Security alert received by the multi-agent system."
    )


# ============================================================
# RESPONSE MODEL
# ============================================================

class AnalyzeResponse(BaseModel):
    incident_id: str
    threat_summary: str
    techniques: List[Any]
    attack_chain: List[Any]
    confidence: float
    recommended_response: Dict[str, Any]
    explanation: str
    evidence: List[Any]
    limitations: List[str]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def safe_list(value: Any) -> List[Any]:
    """
    Convert an arbitrary value into a safe list.

    Examples:
        None          -> []
        []            -> []
        ["a", "b"]    -> ["a", "b"]
        {"x": 1}      -> [{"x": 1}]
        "technique"   -> ["technique"]
    """

    if value is None:
        return []

    if isinstance(value, list):
        return value

    if isinstance(value, tuple):
        return list(value)

    return [value]


def safe_dict(value: Any) -> Dict[str, Any]:
    """
    Convert an arbitrary value into a dictionary.
    """

    if isinstance(value, dict):
        return dict(value)

    return {}


def safe_string(value: Any, default: str = "") -> str:
    """
    Convert a value into a safe string.
    """

    if value is None:
        return default

    if isinstance(value, str):
        value = value.strip()

        if value:
            return value

        return default

    return str(value)


def safe_confidence(value: Any) -> float:
    """
    Convert confidence into a valid number between 0 and 1.
    """

    try:
        confidence = float(value)
    except (TypeError, ValueError):
        return 0.0

    if not 0.0 <= confidence <= 1.0:
        return 0.0

    return round(confidence, 4)


def extract_threat_summary(
    state: AgentState
) -> str:
    """
    Extract the best available threat summary.
    """

    explanation = safe_dict(
        state.explanation
    )

    detection = safe_dict(
        state.detection
    )

    candidates = [
        explanation.get("threat_summary"),
        explanation.get("summary"),
        explanation.get("behavior_summary"),
        detection.get("behavior_summary"),
        detection.get("threat_summary"),
    ]

    for candidate in candidates:

        value = safe_string(candidate)

        if value:
            return value

    return (
        "Threat summary was not produced by the "
        "available analysis agents."
    )


def extract_techniques(
    state: AgentState
) -> List[Any]:
    """
    Extract techniques from correlation output.

    If correlation does not provide techniques,
    retrieve only explicitly available technique-related
    objects from GraphRAG evidence.
    """

    correlation = safe_dict(
        state.correlation
    )

    techniques = safe_list(
        correlation.get("techniques")
    )

    if techniques:
        return techniques

    threat_intelligence = safe_dict(
        state.threat_intelligence
    )

    retrieved_context = safe_dict(
        threat_intelligence.get(
            "retrieved_context"
        )
    )

    graph_evidence = safe_list(
        retrieved_context.get("evidence")
    )

    extracted = []

    for item in graph_evidence:

        if not isinstance(item, dict):
            continue

        if (
            "technique" in item
            or "technique_id" in item
            or "attack_pattern" in item
        ):
            extracted.append(item)

    return extracted


def extract_attack_chain(
    state: AgentState
) -> List[Any]:
    """
    Extract attack-chain information from
    AttackCorrelationAgent output.
    """

    correlation = safe_dict(
        state.correlation
    )

    return safe_list(
        correlation.get("attack_chain")
    )


def extract_response(
    state: AgentState
) -> Dict[str, Any]:
    """
    Extract response recommendation safely.
    """

    response = safe_dict(
        state.response
    )

    if response:
        return response

    return {
        "status": "unavailable",
        "message": (
            "No response recommendation was produced."
        )
    }


def extract_explanation(
    state: AgentState
) -> str:
    """
    Extract explanation from ExplanationAgent.
    """

    explanation = safe_dict(
        state.explanation
    )

    candidates = [
        explanation.get("explanation"),
        explanation.get("reasoning"),
        explanation.get("summary"),
    ]

    for candidate in candidates:

        value = safe_string(candidate)

        if value:
            return value

    return (
        "No additional explanation was produced."
    )


def extract_evidence(
    state: AgentState
) -> List[Any]:
    """
    Keep observed evidence and retrieved knowledge
    clearly separated.
    """

    final_evidence = []

    detection = safe_dict(
        state.detection
    )

    observed_evidence = safe_list(
        detection.get("observed_evidence")
    )

    for item in observed_evidence:

        final_evidence.append(
            {
                "source_type": "observed_evidence",
                "content": item,
            }
        )

    threat_intelligence = safe_dict(
        state.threat_intelligence
    )

    retrieved_context = safe_dict(
        threat_intelligence.get(
            "retrieved_context"
        )
    )

    retrieved_evidence = safe_list(
        retrieved_context.get("evidence")
    )

    for item in retrieved_evidence:

        final_evidence.append(
            {
                "source_type": "retrieved_knowledge",
                "content": item,
            }
        )

    return final_evidence


def extract_limitations(
    state: AgentState
) -> List[str]:
    """
    Extract unique limitations safely.
    """

    limitations = []

    for item in safe_list(
        state.limitations
    ):

        value = safe_string(item)

        if value and value not in limitations:
            limitations.append(value)

    return limitations


# ============================================================
# HEALTH CHECK
# ============================================================

@app.get("/")
def root() -> Dict[str, str]:

    return {
        "service": "Adaptive Multi-Agent Cyber Defense API",
        "status": "running",
        "endpoint": "/api/agents/analyze",
    }


# ============================================================
# ANALYZE ENDPOINT
# ============================================================

@app.post(
    "/api/agents/analyze",
    response_model=AnalyzeResponse
)
def analyze(
    request: AnalyzeRequest
) -> AnalyzeResponse:

    # --------------------------------------------------------
    # INPUT VALIDATION
    # --------------------------------------------------------

    incident_id = request.incident_id.strip()

    if not incident_id:

        raise HTTPException(
            status_code=400,
            detail="incident_id must not be empty."
        )

    alert = safe_dict(
        request.alert
    )

    if not alert:

        raise HTTPException(
            status_code=400,
            detail="alert must not be empty."
        )

    # --------------------------------------------------------
    # CREATE SHARED STATE
    # --------------------------------------------------------

    try:

        state = AgentState(
            incident_id=incident_id,
            alert=alert,
        )

        # ----------------------------------------------------
        # RUN SUPERVISOR
        # ----------------------------------------------------

        supervisor = Supervisor()

        state = supervisor.analyze(
            state
        )

        # ----------------------------------------------------
        # VERIFY STATE
        # ----------------------------------------------------

        if not isinstance(
            state,
            AgentState
        ):

            raise RuntimeError(
                "Supervisor did not return a valid AgentState."
            )

        # ----------------------------------------------------
        # EXTRACT FINAL RESULTS
        # ----------------------------------------------------

        threat_summary = extract_threat_summary(
            state
        )

        techniques = extract_techniques(
            state
        )

        attack_chain = extract_attack_chain(
            state
        )

        recommended_response = extract_response(
            state
        )

        explanation = extract_explanation(
            state
        )

        evidence = extract_evidence(
            state
        )

        limitations = extract_limitations(
            state
        )

        confidence = safe_confidence(
            state.confidence
        )

        # ----------------------------------------------------
        # FINAL API RESPONSE
        # ----------------------------------------------------

        result = AnalyzeResponse(
            incident_id=state.incident_id,
            threat_summary=threat_summary,
            techniques=techniques,
            attack_chain=attack_chain,
            confidence=confidence,
            recommended_response=recommended_response,
            explanation=explanation,
            evidence=evidence,
            limitations=limitations,
        )

        return result

    # --------------------------------------------------------
    # HTTP ERRORS
    # --------------------------------------------------------

    except HTTPException:
        raise

    # --------------------------------------------------------
    # INTERNAL ERROR
    # --------------------------------------------------------

    except Exception as exc:

        import traceback

        print("\n")
        print("=" * 70)
        print("MULTI-AGENT API INTERNAL ERROR")
        print("=" * 70)

        traceback.print_exc()

        print("=" * 70)
        print("\n")

        raise HTTPException(
            status_code=500,
            detail=(
                "Multi-agent analysis failed. "
                f"Error: {type(exc).__name__}: {str(exc)}"
            ),
        ) from exc