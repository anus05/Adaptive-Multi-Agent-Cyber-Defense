import os
os.environ["GEMINI_API_KEY"] = "DUMMY_KEY_FOR_TEST"

from orchestration.conflict_handler import ConflictHandler
from orchestration.state import AgentState

ch = ConflictHandler()

# Case 1: high detection confidence + low correlation -> conflict
s = AgentState(
    incident_id="INC-CF-001",
    detection={"confidence": 0.9, "severity": "high"},
    correlation={"confidence": 0.2},
    response={"response_priority": "high"},
    explanation={"confidence": 0.7}
)
conflicts = ch.detect_conflicts(s)
print("Case1 conflicts:", len(conflicts))
assert any(c["type"] == "confidence_disagreement" for c in conflicts)
print("PASS: ConflictHandler detected confidence_disagreement")

# Case 2: severity=high, response_priority=low -> mismatch
s2 = AgentState(
    incident_id="INC-CF-002",
    detection={"confidence": 0.4, "severity": "high"},
    correlation={"confidence": 0.4},
    response={"response_priority": "low"},
    explanation={"confidence": 0.4}
)
conflicts2 = ch.detect_conflicts(s2)
print("Case2 conflicts:", len(conflicts2))
assert any(c["type"] == "severity_priority_disagreement" for c in conflicts2)
print("PASS: ConflictHandler detected severity_priority_disagreement")

# Case 3: no conflict
s3 = AgentState(
    incident_id="INC-CF-003",
    detection={"confidence": 0.8, "severity": "high"},
    correlation={"confidence": 0.75},
    response={"response_priority": "high", "confidence": 0.8},
    explanation={"confidence": 0.8}
)
conflicts3 = ch.detect_conflicts(s3)
print("Case3 conflicts:", len(conflicts3))
assert len(conflicts3) == 0
print("PASS: ConflictHandler found no conflict when agents agree")

# Case 4: no-conflict resolve (no LLM call)
result = ch.resolve(s3)
assert result["conflict_detected"] == False
fc = result["final_confidence"]
print("Final confidence (no conflict):", fc)
assert 0.0 <= fc <= 1.0
print("PASS: ConflictHandler.resolve (no conflict) returns valid structure")

print()
print("ALL CONFLICT HANDLER TESTS PASSED")
