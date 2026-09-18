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
    "gemini-3.6-flash"
)


if not api_key:
    raise ValueError(
        f"GEMINI_API_KEY was not found.\n"
        f"Expected .env file at:\n{ENV_FILE}\n\n"
        "Make sure your .env contains:\n"
        "GEMINI_API_KEY=your_api_key"
    )


# ==================================================
# GEMINI CLIENT
# ==================================================

client = genai.Client(
    api_key=api_key
)


# ==================================================
# LLM FUNCTION
# ==================================================

def ask_llm(prompt: str) -> str:
    """
    Send a text prompt to Gemini and return
    the generated text.

    Temporary Gemini 503 errors are retried
    automatically.
    """

    if not isinstance(prompt, str):
        raise TypeError("Prompt must be a string.")

    if not prompt.strip():
        raise ValueError("Prompt cannot be empty.")

    max_retries = 4

    for attempt in range(max_retries):

        try:
            response = client.models.generate_content(
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

        # Client-side errors such as quota/authentication
        except errors.ClientError as exc:

            # Retry only temporary 503 if exposed as ClientError.
            if exc.code == 503 and attempt < max_retries - 1:

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

    raise RuntimeError(
        "Gemini request failed after all retry attempts."
    )