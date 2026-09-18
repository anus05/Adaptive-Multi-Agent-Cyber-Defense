import json
from collections import defaultdict

FILE_PATH = "data/processed/train_clean.jsonl"

# Languages we want to inspect
TARGET_LANGUAGES = {
    "fr", "de", "ca", "cy", "pt", "it",
    "es", "nl", "sv", "hr", "da", "so",
    "no", "id", "ro", "sl", "sq", "af",
    "lt", "tl", "fi", "et"
}

samples = defaultdict(list)

with open(FILE_PATH, "r", encoding="utf-8") as f:

    for line in f:

        record = json.loads(line)

        language = record.get("language", "unknown")

        if language in TARGET_LANGUAGES:

            if len(samples[language]) < 5:
                samples[language].append(record)


print("=" * 70)
print("NON-ENGLISH LANGUAGE SAMPLE CHECK")
print("=" * 70)

for language, records in sorted(samples.items()):

    print(f"\n\nLANGUAGE: {language}")
    print("-" * 50)

    for record in records:

        print(f"ID: {record.get('id')}")
        print(f"TEXT: {record.get('text')}")
        print()