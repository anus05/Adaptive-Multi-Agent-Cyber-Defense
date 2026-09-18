from models.llm_client import ask_llm


def main():

    prompt = """
You are a cybersecurity analyst.

Analyze this threat information:

"Shamoon 2 attacks are associated with credential theft."

Give:
1. Threat name
2. Possible attack behavior
3. Short explanation

Keep the answer concise.
"""

    result = ask_llm(prompt)

    print("=" * 60)
    print("GEMINI TEST")
    print("=" * 60)
    print(result)


if __name__ == "__main__":
    main()