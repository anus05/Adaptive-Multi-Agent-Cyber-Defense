"""
Fix 3 verification — tests 429 retry logic using unittest.mock.
No real API calls made. time.sleep is mocked to avoid actual waits.

Updated after Fix 4: patches _get_client() to return a mock client,
since the module-level 'client' variable was removed.
"""

import os
import sys
from unittest.mock import patch, MagicMock

os.environ["GEMINI_API_KEY"] = "DUMMY_KEY_FOR_TEST"

# Force fresh import
for mod in list(sys.modules.keys()):
    if "llm_client" in mod or ("models" in mod and "llm" in mod.lower()):
        del sys.modules[mod]

import models.llm_client as llm_mod
from google.genai import errors as genai_errors


# -----------------------------------------------------------------------
# Real exception subclasses matching the SDK constructor:
#   APIError.__init__(self, code: int, response_json: Any, response=None)
# -----------------------------------------------------------------------

class FakeClientError(genai_errors.ClientError):
    def __init__(self, code):
        super().__init__(code, {}, None)
        self.code = code

    def __str__(self):
        return f"FakeClientError(code={self.code})"


class FakeServerError(genai_errors.ServerError):
    def __init__(self):
        super().__init__(503, {}, None)

    def __str__(self):
        return "FakeServerError(503)"


PASS = 0
FAIL = 0


def check(label, cond, detail=""):
    global PASS, FAIL
    if cond:
        print(f"[PASS] {label}")
        PASS += 1
    else:
        print(f"[FAIL] {label}: {detail}")
        FAIL += 1


def make_mock_client(side_effect):
    """Build a mock client whose .models.generate_content raises side_effect."""
    mock_client = MagicMock()
    mock_client.models.generate_content.side_effect = side_effect
    return mock_client


# -----------------------------------------------------------------------
# Test 1: 429 is retried exactly max_429_retries (2) times → 3 calls total
# -----------------------------------------------------------------------

calls_429 = []


def always_429(*args, **kwargs):
    calls_429.append(1)
    raise FakeClientError(429)


with patch("models.llm_client._get_client", return_value=make_mock_client(always_429)):
    with patch("models.llm_client.time") as mock_time:
        try:
            llm_mod.ask_llm("test")
            check("429 should raise after retries exhausted", False, "no exception raised")
        except Exception:
            sleeps = [c[0][0] for c in mock_time.sleep.call_args_list]
            check(
                "FIX3: 429 retried exactly 2 times (3 calls total)",
                len(calls_429) == 3,
                f"got {len(calls_429)} calls"
            )
            check(
                "FIX3: 429 each sleep is 60 seconds",
                sleeps == [60, 60],
                f"got {sleeps}"
            )


# -----------------------------------------------------------------------
# Test 2: 503 via ClientError — backoff unchanged: 15, 30, 45 seconds
# -----------------------------------------------------------------------

calls_503c = []


def always_503_client(*args, **kwargs):
    calls_503c.append(1)
    raise FakeClientError(503)


with patch("models.llm_client._get_client", return_value=make_mock_client(always_503_client)):
    with patch("models.llm_client.time") as mock_time_503c:
        try:
            llm_mod.ask_llm("test")
        except Exception:
            sleeps_503c = [c[0][0] for c in mock_time_503c.sleep.call_args_list]
            check(
                "FIX3: 503 ClientError backoff unchanged [15, 30, 45]",
                sleeps_503c == [15, 30, 45],
                f"got {sleeps_503c}"
            )


# -----------------------------------------------------------------------
# Test 3: 503 via ServerError — backoff also unchanged
# -----------------------------------------------------------------------

calls_503s = []


def always_503_server(*args, **kwargs):
    calls_503s.append(1)
    raise FakeServerError()


with patch("models.llm_client._get_client", return_value=make_mock_client(always_503_server)):
    with patch("models.llm_client.time") as mock_time_srv:
        try:
            llm_mod.ask_llm("test")
        except Exception:
            sleeps_srv = [c[0][0] for c in mock_time_srv.sleep.call_args_list]
            check(
                "FIX3: 503 ServerError backoff unchanged [15, 30, 45]",
                sleeps_srv == [15, 30, 45],
                f"got {sleeps_srv}"
            )


# -----------------------------------------------------------------------
# Test 4: 401 propagates immediately (not retried)
# -----------------------------------------------------------------------

calls_401 = []


def always_401(*args, **kwargs):
    calls_401.append(1)
    raise FakeClientError(401)


with patch("models.llm_client._get_client", return_value=make_mock_client(always_401)):
    with patch("models.llm_client.time") as mock_time_401:
        try:
            llm_mod.ask_llm("test")
        except Exception:
            check(
                "FIX3: 401 propagates immediately (1 call only)",
                len(calls_401) == 1,
                f"calls: {len(calls_401)}"
            )
            check(
                "FIX3: 401 does not sleep",
                mock_time_401.sleep.call_count == 0,
                f"sleep called {mock_time_401.sleep.call_count} times"
            )


# -----------------------------------------------------------------------
# Test 5: 429 succeeds on the third attempt
# -----------------------------------------------------------------------

_seq = [FakeClientError(429), FakeClientError(429), None]
_seq_idx = [0]


def sometimes_429(*args, **kwargs):
    exc = _seq[_seq_idx[0]]
    _seq_idx[0] += 1
    if exc is not None:
        raise exc
    return type("R", (), {"text": "OK"})()


with patch("models.llm_client._get_client", return_value=make_mock_client(sometimes_429)):
    with patch("models.llm_client.time"):
        result = llm_mod.ask_llm("test")
        check(
            "FIX3: 429 retry succeeds on third attempt",
            result == "OK",
            f"got: {result}"
        )


# -----------------------------------------------------------------------
# Test 6: Input guards still work
# -----------------------------------------------------------------------

try:
    llm_mod.ask_llm(123)
    check("FIX3: TypeError guard", False, "no exception raised")
except TypeError:
    check("FIX3: TypeError guard still works", True)

try:
    llm_mod.ask_llm("")
    check("FIX3: empty prompt guard", False, "no exception raised")
except ValueError:
    check("FIX3: empty prompt ValueError still works", True)

try:
    llm_mod.ask_llm("   ")
    check("FIX3: whitespace prompt guard", False, "no exception raised")
except ValueError:
    check("FIX3: whitespace prompt ValueError still works", True)


# -----------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------

print()
print("=" * 60)
print(f"FIX 3 RESULTS: {PASS} passed, {FAIL} failed")
print("=" * 60)

sys.exit(0 if FAIL == 0 else 1)
