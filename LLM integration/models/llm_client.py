import os
import time
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import errors


# ==================================================
# PROJECT CONFIGURATION
# ==================================================

BASE_DIR = Path(__file__).resolve().parents[1]
ENV_FILE = BASE_DIR / ".env"

load_dotenv(dotenv_path=ENV_FILE)


# ==================================================
# GEMINI CONFIGURATION
# ==================================================

api_key = os.getenv("GEMINI_API_KEY")

model_name = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.6-flash"      # Override via GEMINI_MODEL in .env if needed
)



# ==================================================
# GEMINI CLIENT (lazy — created on first ask_llm call)
# ==================================================

_client = None


def _get_client() -> "genai.Client":
    """
    Return the Gemini client, creating it on first use.

    Raises EnvironmentError if GEMINI_API_KEY is absent,
    which keeps the error at call-time rather than import-time.
    This allows agents to be imported for offline/mock tests
    without a .env file being present.
    """

    global _client

    if _client is not None:
        return _client

    if not api_key:
        raise EnvironmentError(
            "GEMINI_API_KEY was not found.\n"
            f"Expected .env file at:\n{ENV_FILE}\n\n"
            "Make sure your .env contains:\n"
            "GEMINI_API_KEY=your_api_key"
        )

    _client = genai.Client(api_key=api_key)
    return _client


# ==================================================
# LLM FUNCTION
# ==================================================

def ask_llm(prompt: str) -> str:
    """
    Send a text prompt to Gemini and return
    the generated text.

    Temporary Gemini 503 errors are retried
    automatically (up to 3 retries, 15/30/45 s backoff).

    Quota/rate-limit 429 errors are retried separately
    (up to 2 retries, 60 s fixed backoff).
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    if not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    max_retries = 4       # for 503 (3 actual retries + 1 final raise)
    max_429_retries = 2   # for 429 quota (2 retries then raise)

    quota_attempt = 0

    for attempt in range(max_retries):

        try:
            response = _get_client().models.generate_content(
                model=model_name,
                contents=prompt
            )

            if not response or not response.text:
                raise RuntimeError(
                    "Gemini returned an empty response."
                )

            return response.text.strip()

        # Temporary server-side Gemini error
        except errors.ServerError as exc:

            if attempt < max_retries - 1:

                wait_time = 15 * (attempt + 1)

                print(
                    f"Gemini temporarily unavailable "
                    f"(503). Retry "
                    f"{attempt + 1}/{max_retries - 1} "
                    f"in {wait_time} seconds..."
                )

                time.sleep(wait_time)

            else:
                raise

        # Client-side errors: quota (429), auth, or other
        except errors.ClientError as exc:

            # Retry temporary 503 surfaced as ClientError.
            if exc.code == 503 and attempt < max_retries - 1:

                wait_time = 15 * (attempt + 1)

                print(
                    f"Gemini temporarily unavailable "
                    f"(503). Retry "
                    f"{attempt + 1}/{max_retries - 1} "
                    f"in {wait_time} seconds..."
                )

                time.sleep(wait_time)

            # Retry quota/rate-limit errors with a longer wait.
            # Cap at max_429_retries to avoid very long delays.
            elif exc.code == 429 and quota_attempt < max_429_retries:

                quota_attempt += 1
                wait_time = 60  # quota resets are slow

                print(
                    f"Gemini quota/rate-limit reached "
                    f"(429). Retry "
                    f"{quota_attempt}/{max_429_retries} "
                    f"in {wait_time} seconds..."
                )

                time.sleep(wait_time)

            else:
                raise

    raise RuntimeError(
        "Gemini request failed after all retry attempts."
    )