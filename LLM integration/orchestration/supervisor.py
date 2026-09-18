from orchestration.state import AgentState
from orchestration.conflict_handler import ConflictHandler
from feedback.feedback_manager import FeedbackManager

from agents.detection_agent import DetectionAgent
from agents.threat_intelligence_agent import ThreatIntelligenceAgent
from agents.attack_correlation_agent import AttackCorrelationAgent
from agents.response_agent import ResponseAgent
from agents.explanation_agent import ExplanationAgent


class Supervisor:
    """
    Central Supervisor / Orchestrator.

    Controls the complete multi-agent pipeline,
    handles conflicts, and connects the adaptive
    feedback mechanism.

    Pipeline:

        Alert
          ↓
        Detection Agent
          ↓
        Threat Intelligence Agent
          ↓
        GraphRAG
          ↓
        Attack Correlation Agent
          ↓
        Response Agent
          ↓
        Explanation Agent
          ↓
        Conflict Handler
          ↓
        Adaptive Feedback
          ↓
        Final Result
    """

    def __init__(
        self,
        detection_agent=None,
        threat_intelligence_agent=None,
        attack_correlation_agent=None,
        response_agent=None,
        explanation_agent=None,
        conflict_handler=None,
        feedback_manager=None,
    ):

        self.detection_agent = (
            detection_agent
            if detection_agent is not None
            else DetectionAgent()
        )

        self.threat_intelligence_agent = (
            threat_intelligence_agent
            if threat_intelligence_agent is not None
            else ThreatIntelligenceAgent()
        )

        self.attack_correlation_agent = (
            attack_correlation_agent
            if attack_correlation_agent is not None
            else AttackCorrelationAgent()
        )

        self.response_agent = (
            response_agent
            if response_agent is not None
            else ResponseAgent()
        )

        self.explanation_agent = (
            explanation_agent
            if explanation_agent is not None
            else ExplanationAgent()
        )

        self.conflict_handler = (
            conflict_handler
            if conflict_handler is not None
            else ConflictHandler()
        )

        self.feedback_manager = (
            feedback_manager
            if feedback_manager is not None
            else FeedbackManager()
        )

        self.name = "Supervisor"

    # =========================================================
    # MAIN PIPELINE
    # =========================================================

    def analyze(self, state: AgentState) -> AgentState:
        """
        Execute the complete multi-agent cybersecurity pipeline.
        """

        if not isinstance(state, AgentState):
            raise TypeError(
                "Supervisor requires an AgentState object."
            )

        state.set_stage("supervisor_started")

        state.add_message(
            agent=self.name,
            message=(
                "Supervisor started the multi-agent "
                "cybersecurity analysis pipeline."
            ),
        )

        print("\n" + "=" * 60)
        print("SUPERVISOR - MULTI-AGENT PIPELINE")
        print("=" * 60)

        # -----------------------------------------------------
        # 1. Detection
        # -----------------------------------------------------

        print("\n[1/6] Detection Agent")
        print("-" * 40)

        try:
            state = self.detection_agent.analyze(state)

        except Exception as exc:
            state.add_limitation(
                f"Detection Agent failed: {str(exc)}"
            )
            state.set_stage("pipeline_failed_at_detection")

            print(f"[FAILED] Detection Agent")
            print(f"Error: {exc}")

            raise

        print("[OK] Detection Agent completed.")

        if not state.detection:
            state.add_limitation(
                "Pipeline stopped because detection data "
                "was not produced."
            )

            state.set_stage(
                "pipeline_stopped_at_detection"
            )

            print("[FAILED] No detection result produced.")

            return state

        # -----------------------------------------------------
        # 2. Threat Intelligence
        # -----------------------------------------------------

        print("\n[2/6] Threat Intelligence Agent")
        print("-" * 40)

        try:
            state = self.threat_intelligence_agent.analyze(state)

        except Exception as exc:
            state.add_limitation(
                f"Threat Intelligence Agent failed: {str(exc)}"
            )
            state.set_stage(
                "pipeline_failed_at_threat_intelligence"
            )

            print("[FAILED] Threat Intelligence Agent")
            print(f"Error: {exc}")

            raise

        print("[OK] Threat Intelligence Agent completed.")

        if not state.threat_intelligence:
            state.add_limitation(
                "Pipeline stopped because threat intelligence "
                "was not produced."
            )

            state.set_stage(
                "pipeline_stopped_at_threat_intelligence"
            )

            print("[FAILED] No threat intelligence result produced.")

            return state

        # -----------------------------------------------------
        # 3. Attack Correlation
        # -----------------------------------------------------

        print("\n[3/6] Attack Correlation Agent")
        print("-" * 40)

        try:
            state = self.attack_correlation_agent.analyze(state)

        except Exception as exc:
            state.add_limitation(
                f"Attack Correlation Agent failed: {str(exc)}"
            )
            state.set_stage(
                "pipeline_failed_at_correlation"
            )

            print("[FAILED] Attack Correlation Agent")
            print(f"Error: {exc}")

            raise

        print("[OK] Attack Correlation Agent completed.")

        if not state.correlation:
            state.add_limitation(
                "Pipeline stopped because attack correlation "
                "was not produced."
            )

            state.set_stage(
                "pipeline_stopped_at_correlation"
            )

            print("[FAILED] No correlation result produced.")

            return state

        # -----------------------------------------------------
        # 4. Response Recommendation
        # -----------------------------------------------------

        print("\n[4/6] Response Agent")
        print("-" * 40)

        try:
            state = self.response_agent.analyze(state)

        except Exception as exc:
            state.add_limitation(
                f"Response Agent failed: {str(exc)}"
            )
            state.set_stage(
                "pipeline_failed_at_response"
            )

            print("[FAILED] Response Agent")
            print(f"Error: {exc}")

            raise

        print("[OK] Response Agent completed.")

        if not state.response:
            state.add_limitation(
                "Pipeline stopped because response "
                "recommendations were not produced."
            )

            state.set_stage(
                "pipeline_stopped_at_response"
            )

            print("[FAILED] No response recommendation produced.")

            return state

        # -----------------------------------------------------
        # 5. Explanation
        # -----------------------------------------------------

        print("\n[5/6] Explanation Agent")
        print("-" * 40)

        try:
            state = self.explanation_agent.analyze(state)

        except Exception as exc:
            state.add_limitation(
                f"Explanation Agent failed: {str(exc)}"
            )
            state.set_stage(
                "pipeline_failed_at_explanation"
            )

            print("[FAILED] Explanation Agent")
            print(f"Error: {exc}")

            raise

        print("[OK] Explanation Agent completed.")

        if not state.explanation:
            state.add_limitation(
                "Pipeline stopped because explanation "
                "was not produced."
            )

            state.set_stage(
                "pipeline_stopped_at_explanation"
            )

            print("[FAILED] No explanation produced.")

            return state

        # -----------------------------------------------------
        # 6. Conflict Handling
        # -----------------------------------------------------

        print("\n[6/6] Conflict Handler")
        print("-" * 40)

        try:
            conflict_result = self.conflict_handler.resolve(state)

        except Exception as exc:
            state.add_limitation(
                f"Conflict Handler failed: {str(exc)}"
            )
            state.set_stage(
                "pipeline_failed_at_conflict_handling"
            )

            print("[FAILED] Conflict Handler")
            print(f"Error: {exc}")

            raise

        state.feedback["conflict_handling"] = conflict_result

        conflict_detected = bool(
            conflict_result.get(
                "conflict_detected",
                False
            )
        )

        final_confidence = float(
            conflict_result.get(
                "final_confidence",
                0.0
            )
        )

        if not 0.0 <= final_confidence <= 1.0:
            final_confidence = 0.0

        if conflict_detected:

            state.add_limitation(
                "A disagreement was detected between "
                "agent outputs and additional reasoning "
                "was requested."
            )

            state.add_message(
                agent=self.name,
                message=(
                    "Agent disagreement detected. "
                    "Conflict Handler performed additional reasoning."
                ),
                confidence=final_confidence,
            )

            print("[OK] Conflict detected and resolved.")

        else:

            state.add_message(
                agent=self.name,
                message=(
                    "Conflict check completed with no "
                    "significant disagreement."
                ),
                confidence=final_confidence,
            )

            print("[OK] No significant conflict detected.")

        # -----------------------------------------------------
        # Final Confidence
        # -----------------------------------------------------

        state.confidence = final_confidence

        # -----------------------------------------------------
        # Prepare Adaptive Feedback
        # -----------------------------------------------------

        recommended_actions = state.response.get(
            "recommended_actions",
            []
        )

        if isinstance(recommended_actions, list):

            recommendation_text = "; ".join(
                str(action)
                for action in recommended_actions
            )

        else:

            recommendation_text = str(
                recommended_actions
            )

        state.feedback["pending_feedback"] = {
            "incident_id": state.incident_id,
            "recommendation": recommendation_text,
            "action": recommendation_text,
            "outcome": None,
            "success": None,
            "analyst_feedback": "",
            "confidence": state.confidence,
        }

        # -----------------------------------------------------
        # Pipeline Complete
        # -----------------------------------------------------

        state.set_stage("pipeline_complete")

        state.add_message(
            agent=self.name,
            message=(
                "Supervisor completed the complete "
                "multi-agent cybersecurity analysis pipeline."
            ),
            confidence=state.confidence,
        )

        print("\n" + "=" * 60)
        print("PIPELINE COMPLETE")
        print("=" * 60)

        print(
            f"Incident ID       : {state.incident_id}"
        )

        print(
            f"Detection         : {'OK' if state.detection else 'FAILED'}"
        )

        print(
            "Threat Intelligence: "
            f"{'OK' if state.threat_intelligence else 'FAILED'}"
        )

        print(
            f"Correlation       : {'OK' if state.correlation else 'FAILED'}"
        )

        print(
            f"Response          : {'OK' if state.response else 'FAILED'}"
        )

        print(
            f"Explanation       : {'OK' if state.explanation else 'FAILED'}"
        )

        print(
            f"Confidence        : {state.confidence}"
        )

        print(
            f"Agent Messages    : {len(state.agent_messages)}"
        )

        print(
            f"Current Stage     : {state.current_stage}"
        )

        print("=" * 60)

        return state

    # =========================================================
    # RECORD ACTUAL RESPONSE OUTCOME
    # =========================================================

    def record_outcome(
        self,
        state: AgentState,
        outcome: str,
        success: bool,
        analyst_feedback: str = "",
    ) -> AgentState:
        """
        Record the actual outcome of the recommended response.

        This method does not execute any security action.
        It only records feedback and updates the adaptive policy.
        """

        if not isinstance(state, AgentState):
            raise TypeError(
                "record_outcome requires an AgentState object."
            )

        if not isinstance(outcome, str) or not outcome.strip():
            raise ValueError(
                "outcome must be a non-empty string."
            )

        if not isinstance(success, bool):
            raise TypeError(
                "success must be True or False."
            )

        pending_feedback = state.feedback.get(
            "pending_feedback",
            {}
        )

        recommendation = pending_feedback.get(
            "recommendation",
            ""
        )

        action = pending_feedback.get(
            "action",
            ""
        )

        if not recommendation:
            recommendation = (
                "No response recommendation was recorded."
            )

        if not action:
            action = (
                "No response action was recorded."
            )

        feedback_record = (
            self.feedback_manager.record_feedback(
                incident_id=state.incident_id,
                recommendation=recommendation,
                action=action,
                outcome=outcome,
                success=success,
                analyst_feedback=analyst_feedback,
                confidence=state.confidence,
            )
        )

        updated_policy = (
            self.feedback_manager.get_policy(
                recommendation
            )
        )

        state.feedback["outcome"] = feedback_record

        state.feedback["adaptive_policy"] = (
            updated_policy
        )

        state.feedback["adaptation_status"] = (
            "policy_updated"
        )

        state.add_message(
            agent=self.name,
            message=(
                "Response outcome recorded and adaptive "
                "policy updated."
            ),
            confidence=state.confidence,
        )

        state.set_stage(
            "feedback_recorded"
        )

        return state