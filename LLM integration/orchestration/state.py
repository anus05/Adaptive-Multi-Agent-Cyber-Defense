from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone


@dataclass
class AgentState:
    """
    Shared state passed through the Member 3 multi-agent pipeline.

    Agents should read from and update this state rather than
    directly calling other agents.
    """

    # ---------------------------------------------------------
    # Incident information
    # ---------------------------------------------------------

    incident_id: str
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Original security alert
    alert: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------
    # Member 1 detection information
    # ---------------------------------------------------------

    detection: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------
    # Member 2 GraphRAG information
    # ---------------------------------------------------------

    graph_context: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------
    # Member 3 agent outputs
    # ---------------------------------------------------------

    threat_intelligence: Dict[str, Any] = field(default_factory=dict)

    correlation: Dict[str, Any] = field(default_factory=dict)

    response: Dict[str, Any] = field(default_factory=dict)

    explanation: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------
    # Agent communication / audit trail
    # ---------------------------------------------------------

    agent_messages: List[Dict[str, Any]] = field(default_factory=list)

    # ---------------------------------------------------------
    # Overall confidence
    # ---------------------------------------------------------

    confidence: float = 0.0

    # ---------------------------------------------------------
    # Current pipeline stage
    # ---------------------------------------------------------

    current_stage: str = "initialized"

    # ---------------------------------------------------------
    # Adaptive feedback
    # ---------------------------------------------------------

    feedback: Dict[str, Any] = field(default_factory=dict)

    # ---------------------------------------------------------
    # Limitations / warnings
    # ---------------------------------------------------------

    limitations: List[str] = field(default_factory=list)

    def add_message(
        self,
        agent: str,
        message: str,
        confidence: Optional[float] = None,
    ) -> None:
        """
        Add a structured message to the agent communication log.
        """

        entry = {
            "agent": agent,
            "message": message,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        if confidence is not None:
            entry["confidence"] = confidence

        self.agent_messages.append(entry)

    def set_stage(self, stage: str) -> None:
        """
        Update the current pipeline stage.
        """

        self.current_stage = stage

    def add_limitation(self, limitation: str) -> None:
        """
        Add a limitation or warning if it is not already present.
        """

        if limitation not in self.limitations:
            self.limitations.append(limitation)

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the shared state into a dictionary.
        """

        return {
            "incident_id": self.incident_id,
            "timestamp": self.timestamp,
            "alert": self.alert,
            "detection": self.detection,
            "graph_context": self.graph_context,
            "threat_intelligence": self.threat_intelligence,
            "correlation": self.correlation,
            "response": self.response,
            "explanation": self.explanation,
            "agent_messages": self.agent_messages,
            "confidence": self.confidence,
            "current_stage": self.current_stage,
            "feedback": self.feedback,
            "limitations": self.limitations,
        }