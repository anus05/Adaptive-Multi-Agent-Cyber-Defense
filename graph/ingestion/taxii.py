import json
from pathlib import Path

import requests


# ============================================================
# MITRE ATT&CK TAXII 2.1
# ============================================================

TAXII_ROOT = "https://attack-taxii.mitre.org"

API_ROOT = f"{TAXII_ROOT}/api/v21"


# ============================================================
# OUTPUT PATH
# ============================================================

OUTPUT_DIR = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "stix"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "taxii_enterprise_relationships.json"
)


# ============================================================
# TAXII HEADERS
# ============================================================

HEADERS = {
    "Accept": "application/taxii+json;version=2.1"
}


# ============================================================
# Helper: GET JSON
# ============================================================

def get_json(url, params=None):

    response = requests.get(
        url,
        headers=HEADERS,
        params=params,
        timeout=60
    )

    print()
    print(
        "GET:",
        response.url
    )

    print(
        "HTTP status:",
        response.status_code
    )

    response.raise_for_status()

    return response.json()


# ============================================================
# Step 1 — TAXII Discovery
# ============================================================

def discover():

    print()
    print("=" * 60)
    print("TAXII DISCOVERY")
    print("=" * 60)

    url = f"{TAXII_ROOT}/taxii2/"

    data = get_json(url)

    print(
        "Title:",
        data.get("title")
    )

    print(
        "Default API root:",
        data.get("default")
    )

    return data


# ============================================================
# Step 2 — Get Collections
# ============================================================

def get_collections():

    print()
    print("=" * 60)
    print("TAXII COLLECTIONS")
    print("=" * 60)

    url = f"{API_ROOT}/collections/"

    data = get_json(url)

    collections = data.get(
        "collections",
        []
    )

    print(
        "Collections found:",
        len(collections)
    )

    for collection in collections:

        print(
            collection.get("title"),
            "|",
            collection.get("id")
        )

    return collections


# ============================================================
# Step 3 — Find Enterprise ATT&CK
# ============================================================

def find_enterprise_collection(collections):

    for collection in collections:

        title = collection.get(
            "title",
            ""
        ).strip().lower()

        if "enterprise" in title:

            return collection

    return None


# ============================================================
# Step 4 — Download Relationships
# ============================================================

def get_relationships(collection_id):

    print()
    print("=" * 60)
    print("DOWNLOADING ENTERPRISE ATT&CK RELATIONSHIPS")
    print("=" * 60)

    url = (
        f"{API_ROOT}/collections/"
        f"{collection_id}/objects/"
    )

    params = {
        "limit": 100,
        "match[type]": "relationship"
    }

    data = get_json(
        url,
        params=params
    )

    objects = data.get(
        "objects",
        []
    )

    print()
    print(
        "STIX objects received:",
        len(objects)
    )

    print(
        "More available:",
        data.get("more")
    )

    return data


# ============================================================
# Step 5 — Count STIX Types
# ============================================================

def count_types(objects):

    counts = {}

    for obj in objects:

        object_type = obj.get(
            "type",
            "unknown"
        )

        counts[object_type] = (
            counts.get(
                object_type,
                0
            ) + 1
        )

    return counts


# ============================================================
# Step 6 — Display Relationships
# ============================================================

def display_relationships(objects):

    print()
    print("=" * 60)
    print("RELATIONSHIP EXAMPLES")
    print("=" * 60)

    for index, obj in enumerate(
        objects[:10],
        start=1
    ):

        print()
        print(
            f"{index}. Relationship"
        )

        print(
            "ID:",
            obj.get("id")
        )

        print(
            "Relationship type:",
            obj.get("relationship_type")
        )

        print(
            "Source:",
            obj.get("source_ref")
        )

        print(
            "Target:",
            obj.get("target_ref")
        )

        print(
            "Created:",
            obj.get("created")
        )

        print(
            "Modified:",
            obj.get("modified")
        )


# ============================================================
# Step 7 — Save Data
# ============================================================

def save_data(
    data,
    enterprise_id
):

    objects = data.get(
        "objects",
        []
    )

    output = {

        "source":
            "MITRE ATT&CK TAXII 2.1",

        "api_root":
            API_ROOT,

        "collection_id":
            enterprise_id,

        "filter":
            "relationship",

        "object_count":
            len(objects),

        "objects":
            objects
    }

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            output,
            file,
            indent=2,
            ensure_ascii=False
        )

    print()
    print("=" * 60)

    print(
        "Saved to:"
    )

    print(
        OUTPUT_FILE
    )


# ============================================================
# Main
# ============================================================

def main():

    print()
    print("#" * 60)
    print("# MITRE ATT&CK TAXII 2.1")
    print("# RELATIONSHIP INGESTION")
    print("#" * 60)

    # --------------------------------------------------------
    # Discovery
    # --------------------------------------------------------

    discover()

    # --------------------------------------------------------
    # Collections
    # --------------------------------------------------------

    collections = get_collections()

    # --------------------------------------------------------
    # Find Enterprise
    # --------------------------------------------------------

    enterprise = (
        find_enterprise_collection(
            collections
        )
    )

    if not enterprise:

        print()

        print(
            "❌ Enterprise ATT&CK collection "
            "not found."
        )

        return

    enterprise_id = enterprise.get(
        "id"
    )

    print()
    print(
        "Enterprise collection:"
    )

    print(
        enterprise.get("title")
    )

    print(
        "Collection ID:",
        enterprise_id
    )

    # --------------------------------------------------------
    # Download relationships
    # --------------------------------------------------------

    data = get_relationships(
        enterprise_id
    )

    objects = data.get(
        "objects",
        []
    )

    # --------------------------------------------------------
    # Count types
    # --------------------------------------------------------

    counts = count_types(
        objects
    )

    print()
    print("=" * 60)
    print("STIX OBJECT TYPES")
    print("=" * 60)

    for object_type, count in sorted(
        counts.items()
    ):

        print(
            f"{object_type:30} {count}"
        )

    # --------------------------------------------------------
    # Verify relationships
    # --------------------------------------------------------

    relationship_count = sum(
        1
        for obj in objects
        if obj.get("type") == "relationship"
    )

    print()
    print(
        "Relationship objects:",
        relationship_count
    )

    # --------------------------------------------------------
    # Display examples
    # --------------------------------------------------------

    display_relationships(
        objects
    )

    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    save_data(
        data,
        enterprise_id
    )

    # --------------------------------------------------------
    # Final status
    # --------------------------------------------------------

    print()
    print(
        "✅ TAXII relationship ingestion completed"
    )


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except requests.exceptions.RequestException as e:

        print()
        print(
            "❌ TAXII request failed:"
        )

        print(e)

    except Exception as e:

        print()
        print(
            "❌ Unexpected error:"
        )

        print(e)