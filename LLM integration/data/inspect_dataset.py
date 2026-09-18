import json

file_path = "data/raw/train.jsonl"

with open(file_path, "r", encoding="utf-8") as f:
    for i in range(3):
        line = f.readline()

        if not line:
            break

        record = json.loads(line)

        print(f"\n--- Record {i + 1} ---")
        print("Keys:", record.keys())
        print(json.dumps(record, indent=2, ensure_ascii=False))