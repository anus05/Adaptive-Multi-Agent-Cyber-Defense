import json
from pathlib import Path

import requests


# ============================================================
# NVD API
# ============================================================

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# ============================================================
# Project paths
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

OUTPUT_DIR = PROJECT_ROOT / "data" / "nvd"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = OUTPUT_DIR / "nvd_sample.json"


# ============================================================
# Download CVEs from NVD
# ============================================================

def download_cves():

    print("Downloading CVE data from NVD...")

    params = {
        "resultsPerPage": 100,
        "startIndex": 0,
        "keywordSearch": "apache"
    }

    response = requests.get(
        NVD_URL,
        params=params,
        timeout=60
    )

    print("HTTP status:", response.status_code)

    response.raise_for_status()

    return response.json()


# ============================================================
# Parse CPE 2.3
# ============================================================

def parse_cpe(cpe_string):

    """
    Example:

    cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*

    Returns:

    {
        "vendor": "apache",
        "product": "http_server",
        "version": "2.4.49"
    }
    """

    if not cpe_string:
        return None

    parts = cpe_string.split(":")

    # CPE 2.3 should contain at least 6 parts
    if len(parts) < 6:
        return None

    # Verify this is actually a CPE
    if parts[0] != "cpe" or parts[1] != "2.3":
        return None

    return {
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5]
    }


# ============================================================
# Extract affected products
# ============================================================

def extract_products(cve):

    products = []

    configurations = cve.get(
        "configurations",
        []
    )

    # --------------------------------------------------------
    # Recursive function for NVD configuration nodes
    # --------------------------------------------------------

    def process_nodes(nodes):

        for node in nodes:

            # ------------------------------------------------
            # Extract CPE matches
            # ------------------------------------------------

            cpe_matches = node.get(
                "cpeMatch",
                []
            )

            for cpe_match in cpe_matches:

                # Only include vulnerable products
                if not cpe_match.get(
                    "vulnerable",
                    True
                ):
                    continue

                criteria = cpe_match.get(
                    "criteria"
                )

                if not criteria:
                    continue

                parsed = parse_cpe(criteria)

                if not parsed:
                    continue

                product = {
                    "cpe": criteria,
                    "vendor": parsed["vendor"],
                    "product": parsed["product"],
                    "version": parsed["version"]
                }

                products.append(product)

            # ------------------------------------------------
            # Handle nested child nodes
            # ------------------------------------------------

            children = node.get(
                "children",
                []
            )

            if children:

                process_nodes(children)

    # --------------------------------------------------------
    # Process every configuration
    # --------------------------------------------------------

    for configuration in configurations:

        nodes = configuration.get(
            "nodes",
            []
        )

        process_nodes(nodes)

    # --------------------------------------------------------
    # Remove duplicates
    # --------------------------------------------------------

    unique_products = {}

    for product in products:

        unique_products[
            product["cpe"]
        ] = product

    return list(
        unique_products.values()
    )


# ============================================================
# Extract CVE information
# ============================================================

def extract_cves(data):

    vulnerabilities = data.get(
        "vulnerabilities",
        []
    )

    cves = []

    for item in vulnerabilities:

        cve = item.get(
            "cve",
            {}
        )

        # ====================================================
        # CVE ID
        # ====================================================

        cve_id = cve.get("id")

        if not cve_id:
            continue

        # ====================================================
        # Description
        # ====================================================

        description = ""

        descriptions = cve.get(
            "descriptions",
            []
        )

        for desc in descriptions:

            if desc.get("lang") == "en":

                description = desc.get(
                    "value",
                    ""
                )

                break

        # ====================================================
        # CVSS
        # ====================================================

        cvss_score = None
        cvss_severity = None

        metrics = cve.get(
            "metrics",
            {}
        )

        # Prefer CVSS v4
        if "cvssMetricV40" in metrics:

            metric_list = metrics[
                "cvssMetricV40"
            ]

            if metric_list:

                metric = metric_list[0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                cvss_score = cvss_data.get(
                    "baseScore"
                )

                cvss_severity = cvss_data.get(
                    "baseSeverity"
                )

        # Otherwise use CVSS v3.1
        elif "cvssMetricV31" in metrics:

            metric_list = metrics[
                "cvssMetricV31"
            ]

            if metric_list:

                metric = metric_list[0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                cvss_score = cvss_data.get(
                    "baseScore"
                )

                cvss_severity = cvss_data.get(
                    "baseSeverity"
                )

        # Otherwise try CVSS v3.0
        elif "cvssMetricV30" in metrics:

            metric_list = metrics[
                "cvssMetricV30"
            ]

            if metric_list:

                metric = metric_list[0]

                cvss_data = metric.get(
                    "cvssData",
                    {}
                )

                cvss_score = cvss_data.get(
                    "baseScore"
                )

                cvss_severity = cvss_data.get(
                    "baseSeverity"
                )

        # ====================================================
        # Weakness / CWE
        # ====================================================

        weaknesses = []

        for weakness in cve.get(
            "weaknesses",
            []
        ):

            for weakness_description in weakness.get(
                "description",
                []
            ):

                value = weakness_description.get(
                    "value"
                )

                if value:

                    weaknesses.append(
                        value
                    )

        # Remove duplicate weaknesses
        weaknesses = list(
            dict.fromkeys(weaknesses)
        )

        # ====================================================
        # References
        # ====================================================

        references = []

        for reference in cve.get(
            "references",
            []
        ):

            url = reference.get(
                "url"
            )

            if url:

                references.append(
                    url
                )

        # Remove duplicate references
        references = list(
            dict.fromkeys(references)
        )

        # ====================================================
        # Affected products
        # ====================================================

        products = extract_products(
            cve
        )

        # ====================================================
        # Create normalized CVE object
        # ====================================================

        cves.append({

            "cve_id": cve_id,

            "description": description,

            "cvss_score": cvss_score,

            "cvss_severity": cvss_severity,

            "weaknesses": weaknesses,

            "products": products,

            "references": references,

            "published": cve.get(
                "published"
            ),

            "last_modified": cve.get(
                "lastModified"
            )
        })

    return cves


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 60)
    print("NVD CVE INGESTION")
    print("=" * 60)

    # --------------------------------------------------------
    # Download
    # --------------------------------------------------------

    data = download_cves()

    print()

    print(
        "Total vulnerabilities returned:",
        data.get("totalResults")
    )

    # --------------------------------------------------------
    # Extract
    # --------------------------------------------------------

    cves = extract_cves(
        data
    )

    print(
        "CVEs extracted:",
        len(cves)
    )

    # --------------------------------------------------------
    # Count products
    # --------------------------------------------------------

    total_products = sum(
        len(cve.get("products", []))
        for cve in cves
    )

    print(
        "Affected products extracted:",
        total_products
    )

    # --------------------------------------------------------
    # Keep first 20 CVEs
    # --------------------------------------------------------

    cves = cves[:20]

    print()

    print(
        "CVEs saved:",
        len(cves)
    )

    # --------------------------------------------------------
    # Count products in saved CVEs
    # --------------------------------------------------------

    total_products = sum(
        len(cve.get("products", []))
        for cve in cves
    )

    print(
        "Products saved:",
        total_products
    )

    # --------------------------------------------------------
    # Save JSON
    # --------------------------------------------------------

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            cves,
            file,
            indent=2,
            ensure_ascii=False
        )

    # --------------------------------------------------------
    # Display result
    # --------------------------------------------------------

    print()

    print(
        "Saved to:"
    )

    print(
        OUTPUT_FILE
    )

    # --------------------------------------------------------
    # Display examples
    # --------------------------------------------------------

    print()
    print("=" * 60)
    print("EXAMPLE CVE")
    print("=" * 60)

    if cves:

        example = cves[0]

        print(
            "CVE:",
            example["cve_id"]
        )

        print(
            "CVSS:",
            example["cvss_score"]
        )

        print(
            "Severity:",
            example["cvss_severity"]
        )

        print(
            "Products:",
            len(example["products"])
        )

        print(
            "Description:",
            example["description"][:250]
        )

        # ----------------------------------------------------
        # Display first product
        # ----------------------------------------------------

        if example["products"]:

            product = example["products"][0]

            print()
            print("First affected product:")

            print(
                "Vendor:",
                product["vendor"]
            )

            print(
                "Product:",
                product["product"]
            )

            print(
                "Version:",
                product["version"]
            )

            print(
                "CPE:",
                product["cpe"]
            )

        else:

            print()
            print(
                "⚠️ No affected product found "
                "for this CVE."
            )

    print()
    print("=" * 60)
    print("NVD INGESTION COMPLETED")
    print("=" * 60)


# ============================================================
# Entry point
# ============================================================

if __name__ == "__main__":

    try:

        main()

    except requests.exceptions.RequestException as e:

        print()
        print("❌ NVD request failed:")
        print(e)

    except Exception as e:

        print()
        print("❌ Unexpected error:")
        print(e)