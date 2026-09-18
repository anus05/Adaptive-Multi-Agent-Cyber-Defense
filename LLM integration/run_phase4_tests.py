"""
Phase 4 — Structured output parsing tests.
Runs WITHOUT making any real Gemini API call.
A dummy GEMINI_API_KEY is injected only to satisfy the module-level guard.
"""

import json
import os
import sys

os.environ["GEMINI_API_KEY"] = "DUMMY_KEY_FOR_VALIDATION_TEST_ONLY"

from agents.detection_agent import DetectionAgent
from agents.attack_correlation_agent import AttackCorrelationAgent
from agents.response_agent import ResponseAgent
from agents.explanation_agent import ExplanationAgent
from orchestration.conflict_handler import ConflictHandler

PASS = 0
FAIL = 0


def check(label, expr, expected_exc=None):
    global PASS, FAIL
    if expected_exc:
        try:
            expr()
            print(f"[FAIL] {label}: expected {expected_exc.__name__} but no exception raised")
            FAIL += 1
        except expected_exc as e:
            print(f"[PASS] {label}: {expected_exc.__name__} raised correctly")
            PASS += 1
        except Exception as e:
            print(f"[FAIL] {label}: unexpected exception {type(e).__name__}: {e}")
            FAIL += 1
    else:
        try:
            expr()
            print(f"[PASS] {label}")
            PASS += 1
        except Exception as e:
            print(f"[FAIL] {label}: {type(e).__name__}: {e}")
            FAIL += 1


# -----------------------------------------------------------------------
# DETECTION AGENT
# -----------------------------------------------------------------------

print("\n=== DetectionAgent._validate_result ===")

VALID_DET = {
    "is_suspicious": True, "severity": "high",
    "behavior_summary": "SSH brute force", "entities": ["SSH"],
    "observed_evidence": ["multiple failed logins"],
    "inference": ["credential attack"],
    "reasoning": "patterns consistent with brute force",
    "confidence": 0.9, "limitations": []
}

check("valid input", lambda: DetectionAgent._validate_result(VALID_DET))
check("missing all fields", lambda: DetectionAgent._validate_result({}), ValueError)
check("missing severity", lambda: DetectionAgent._validate_result({"is_suspicious": True}), ValueError)
check("confidence > 1.0", lambda: DetectionAgent._validate_result({**VALID_DET, "confidence": 1.5}), ValueError)
check("confidence < 0.0", lambda: DetectionAgent._validate_result({**VALID_DET, "confidence": -0.1}), ValueError)
check("entities not a list", lambda: DetectionAgent._validate_result({**VALID_DET, "entities": "SSH"}), ValueError)
check("observed_evidence not a list", lambda: DetectionAgent._validate_result({**VALID_DET, "observed_evidence": "logins"}), ValueError)
check("inference not a list", lambda: DetectionAgent._validate_result({**VALID_DET, "inference": "maybe"}), ValueError)
check("limitations not a list", lambda: DetectionAgent._validate_result({**VALID_DET, "limitations": "none"}), ValueError)

# JSON parse path (simulating what agent does)
valid_json_str = json.dumps(VALID_DET)
check("valid JSON parses and validates", lambda: DetectionAgent._validate_result(json.loads(valid_json_str)))

# Malformed JSON
def parse_truncated():
    json.loads('{"is_suspicious": true')

check("truncated JSON raises JSONDecodeError", parse_truncated, json.JSONDecodeError)

# Markdown-fenced JSON (common Gemini failure)
def parse_markdown():
    json.loads("```json\n{}\n```")

check("markdown-fenced JSON raises JSONDecodeError", parse_markdown, json.JSONDecodeError)

# Plain text
def parse_plain_text():
    json.loads("This is a plain text response.")

check("plain text raises JSONDecodeError", parse_plain_text, json.JSONDecodeError)


# -----------------------------------------------------------------------
# ATTACK CORRELATION AGENT
# -----------------------------------------------------------------------

print("\n=== AttackCorrelationAgent._validate_result ===")

VALID_CORR = {
    "correlations": [], "attack_chain": [], "observed_behaviors": [],
    "retrieved_techniques": [], "inferences": [],
    "reasoning": "test", "confidence": 0.5, "limitations": []
}

check("valid input", lambda: AttackCorrelationAgent._validate_result(VALID_CORR))
check("missing fields", lambda: AttackCorrelationAgent._validate_result({}), ValueError)
check("correlations not a list", lambda: AttackCorrelationAgent._validate_result({**VALID_CORR, "correlations": "x"}), ValueError)
check("confidence out of range", lambda: AttackCorrelationAgent._validate_result({**VALID_CORR, "confidence": -0.1}), ValueError)
check("confidence > 1.0", lambda: AttackCorrelationAgent._validate_result({**VALID_CORR, "confidence": 2.0}), ValueError)


# -----------------------------------------------------------------------
# RESPONSE AGENT
# -----------------------------------------------------------------------

print("\n=== ResponseAgent._validate_result ===")

VALID_RESP = {
    "response_priority": "high",
    "recommended_actions": [{
        "action": "block IP", "reason": "suspicious", "priority": "high",
        "type": "containment", "reversible": True
    }],
    "immediate_actions": [], "follow_up_actions": [],
    "human_approval_required": True, "execution_status": "recommendation_only",
    "reasoning": "test", "confidence": 0.7, "limitations": []
}

check("valid input", lambda: ResponseAgent._validate_result(VALID_RESP))
check("missing fields", lambda: ResponseAgent._validate_result({}), ValueError)
check("execution_status != recommendation_only",
      lambda: ResponseAgent._validate_result({**VALID_RESP, "execution_status": "auto_execute"}), ValueError)
check("human_approval_required=False",
      lambda: ResponseAgent._validate_result({**VALID_RESP, "human_approval_required": False}), ValueError)
check("invalid response_priority",
      lambda: ResponseAgent._validate_result({**VALID_RESP, "response_priority": "extreme"}), ValueError)
check("recommended_actions not a list",
      lambda: ResponseAgent._validate_result({**VALID_RESP, "recommended_actions": "block"}), ValueError)

# Action missing fields
def action_missing_fields():
    bad = {**VALID_RESP, "recommended_actions": [{"action": "x"}]}
    ResponseAgent._validate_result(bad)

check("action item missing subfields", action_missing_fields, ValueError)

# Action with invalid type
def action_invalid_type():
    bad_action = {
        "action": "nuke it", "reason": "why not", "priority": "critical",
        "type": "destruction", "reversible": False
    }
    ResponseAgent._validate_result({**VALID_RESP, "recommended_actions": [bad_action]})

check("action with invalid type", action_invalid_type, ValueError)

# Action reversible not bool
def action_reversible_not_bool():
    bad_action = {
        "action": "block", "reason": "suspicious", "priority": "high",
        "type": "containment", "reversible": "yes"
    }
    ResponseAgent._validate_result({**VALID_RESP, "recommended_actions": [bad_action]})

check("action reversible not bool", action_reversible_not_bool, ValueError)


# -----------------------------------------------------------------------
# EXPLANATION AGENT
# -----------------------------------------------------------------------

print("\n=== ExplanationAgent._validate_result ===")

VALID_EXP = {
    "summary": "test", "observed_evidence": [], "retrieved_knowledge": [],
    "correlation_explanation": "", "response_explanation": "",
    "inferences": [], "limitations": [], "confidence": 0.8
}

check("valid input", lambda: ExplanationAgent._validate_result(VALID_EXP))
check("missing fields", lambda: ExplanationAgent._validate_result({}), ValueError)
check("observed_evidence not a list",
      lambda: ExplanationAgent._validate_result({**VALID_EXP, "observed_evidence": "x"}), ValueError)
check("confidence > 1.0",
      lambda: ExplanationAgent._validate_result({**VALID_EXP, "confidence": 1.1}), ValueError)


# -----------------------------------------------------------------------
# CONFLICT HANDLER — parse_resolution
# -----------------------------------------------------------------------

print("\n=== ConflictHandler._parse_resolution ===")

valid_resolution = json.dumps({
    "final_confidence": 0.6,
    "resolution": "Confidence gap is acknowledged.",
    "reasoning": "Detection was high-confidence but correlation was weak."
})

check("valid resolution JSON",
      lambda: ConflictHandler._parse_resolution(valid_resolution))

def resolution_missing_fields():
    ConflictHandler._parse_resolution(json.dumps({"final_confidence": 0.5}))

check("resolution missing fields", resolution_missing_fields, ValueError)

def resolution_confidence_out_of_range():
    bad = json.dumps({"final_confidence": 1.5, "resolution": "ok", "reasoning": "ok"})
    ConflictHandler._parse_resolution(bad)

check("resolution confidence > 1.0", resolution_confidence_out_of_range, ValueError)

def resolution_invalid_json():
    ConflictHandler._parse_resolution("not json")

check("resolution invalid JSON", resolution_invalid_json, RuntimeError)


# -----------------------------------------------------------------------
# SUMMARY
# -----------------------------------------------------------------------

print("\n" + "=" * 60)
print(f"PHASE 4 RESULTS: {PASS} passed, {FAIL} failed")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
