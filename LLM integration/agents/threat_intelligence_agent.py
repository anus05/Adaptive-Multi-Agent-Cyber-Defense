import json
from typing import Any, Dict
from urllib import request, error

from orchestration.state import AgentState


class ThreatIntelligenceAgent:
    """
    Threat Intelligence Agent.

    Responsibilities:
    1. Read the Detection Agent result.
    2. Build a threat-intelligence query.
    3. Call Member 2's existing GraphRAG API.
    4. Store the complete GraphRAG response in AgentState.
    5. Clearly separate retrieved knowledge from observed evidence.
    """

    def __init__(
        self,
        graphrag_url: str = "http://127.0.0.1:8002/api/graphrag/query",
    ):
        self.name = "ThreatIntelligenceAgent"
        self.graphrag_url = graphrag_url

    def _build_query(self, detection: Dict[str, Any]) -> str:
        behavior = detection.get("behavior_summary", "")
        entities = detection.get("entities", [])
        observed_evidence = detection.get("observed_evidence", [])

        entity_text = ", ".join(str(item) for item in entities)

        evidence_text = "; ".join(
            str(item) for item in observed_evidence
        )

        return (
            "Provide cybersecurity threat intelligence related to the "
            "following detected behavior. Identify relevant MITRE ATT&CK "
            "techniques, tactics, threat actors, malware, software, "
            "vulnerabilities, or related entities when supported by the "
            "retrieved knowledge.\n\n"
            "IMPORTANT: Retrieved knowledge must not be treated as "
            "observed evidence.\n\n"
            f"Detected behavior: {behavior}\n"
            f"Entities: {entity_text}\n"
            f"Observed evidence: {evidence_text}"
        )

    def _call_graphrag(self, query: str) -> Dict[str, Any]:
        payload = json.dumps(
            {"query": query}
        ).encode("utf-8")

        http_request = request.Request(
            self.graphrag_url,
            data=payload,
            headers={
                "Content-Type": "application/json"
            },
            method="POST",
        )

        try:
            with request.urlopen(
                http_request,
                timeout=120
            ) as response:

                response_body = response.read().decode("utf-8")

                if response.status != 200:
                    raise RuntimeError(
                        f"GraphRAG API returned HTTP {response.status}."
                    )

                result = json.loads(response_body)

        except error.HTTPError as exc:
            body = exc.read().decode(
                "utf-8",
                errors="replace"
            )

            raise RuntimeError(
                f"GraphRAG API HTTP error {exc.code}: {body}"
            ) from exc

        except error.URLError as exc:
            raise RuntimeError(
                "Could not connect to GraphRAG API at "
                f"{self.graphrag_url}. "
                "Make sure Member 2's GraphRAG API is running."
            ) from exc

        except json.JSONDecodeError as exc:
            raise RuntimeError(
                "GraphRAG API returned invalid JSON."
            ) from exc

        if not isinstance(result, dict):
            raise ValueError(
                "GraphRAG API response must be a JSON object."
            )

        return result

    @staticmethod
    def _extract_retrieved_context(
        graphrag_result: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Extract the actual fields returned by Member 2's GraphRAG API.

        The API response contains:
        - evidence
        - llm_context
        - statistics
        """

        retrieved_context = {}

        if "evidence" in graphrag_result:
            retrieved_context["evidence"] = (
                graphrag_result["evidence"]
            )

        if "llm_context" in graphrag_result:
            retrieved_context["llm_context"] = (
                graphrag_result["llm_context"]
            )

        if "statistics" in graphrag_result:
            retrieved_context["statistics"] = (
                graphrag_result["statistics"]
            )

        return retrieved_context

    def analyze(self, state: AgentState) -> AgentState:
        state.set_stage("threat_intelligence")

        if not state.detection:
            limitation = (
                "Threat Intelligence Agent received no "
                "detection result."
            )

            state.add_limitation(limitation)

            state.threat_intelligence = {
                "status": "skipped",
                "reason": "No detection result was available.",
            }

            state.add_message(
                agent=self.name,
                message=(
                    "Threat intelligence analysis skipped "
                    "because detection data was unavailable."
                ),
                confidence=0.0,
            )

            return state

        # Build query from Detection Agent output.
        query = self._build_query(state.detection)

        # Call existing Member 2 GraphRAG API.
        graphrag_result = self._call_graphrag(query)

        # Store the complete response.
        state.graph_context = graphrag_result

        # Extract the actual returned GraphRAG fields.
        retrieved_context = self._extract_retrieved_context(
            graphrag_result
        )

        state.threat_intelligence = {
            "status": "received",
            "query": query,
            "source": "Member 2 GraphRAG API",
            "retrieved_context": retrieved_context,
            "evidence": graphrag_result.get(
                "evidence",
                []
            ),
            "llm_context": graphrag_result.get(
                "llm_context",
                ""
            ),
            "statistics": graphrag_result.get(
                "statistics",
                {}
            ),
        }

        # Preserve limitations if the API response does not
        # contain the expected retrieval fields.
        if not retrieved_context:
            state.add_limitation(
                "GraphRAG returned no recognized retrieval fields."
            )

        state.add_message(
            agent=self.name,
            message=(
                "Threat intelligence retrieved from the "
                "existing GraphRAG API."
            ),
            confidence=state.confidence,
        )

        state.set_stage(
            "threat_intelligence_complete"
        )

        return state