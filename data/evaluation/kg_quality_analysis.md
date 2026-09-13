# Member 2 — Knowledge Graph Quality & Provenance Validation Analysis

**Evaluation Date**: 2026-09-13  
**Database**: Neo4j Community Edition  
**Scope**: Member 2 GraphRAG Cybersecurity Knowledge Graph Audit

---

## A. Knowledge Graph Overview
- **Total Nodes**: `2085`
- **Total Relationships**: `20382`
- **Average Node Degree**: `19.55`
- **Maximum Node Degree**: `524`
- **Connected Graph Ratio**: `96.93%`

---

## B. Node Statistics

| Node Label | Count | Percentage of Graph |
| :--- | :---: | :---: |
| **Technique** | 858 | 41.15% |
| **Malware** | 733 | 35.16% |
| **ThreatActor** | 191 | 9.16% |
| **Tool** | 95 | 4.56% |
| **Campaign** | 56 | 2.69% |
| **CourseOfAction** | 54 | 2.59% |
| **Software** | 41 | 1.97% |
| **CVE** | 40 | 1.92% |
| **Tactic** | 15 | 0.72% |
| **Weakness** | 2 | 0.1% |

---

## C. Relationship Statistics

| Relationship Type | Count | Percentage of Relationships |
| :--- | :---: | :---: |
| **`USES`** | 18555 | 91.04% |
| **`BELONGS_TO`** | 1090 | 5.35% |
| **`SUBTECHNIQUE_OF`** | 477 | 2.34% |
| **`REVOKED_BY`** | 157 | 0.77% |
| **`AFFECTS`** | 54 | 0.26% |
| **`ATTRIBUTED_TO`** | 28 | 0.14% |
| **`HAS_WEAKNESS`** | 21 | 0.1% |

---

## D. Connectivity Analysis
- **Total Graph Nodes**: `2085`
- **Total Graph Relationships**: `20382`
- **Connected Nodes (Degree > 0)**: `2021` (`96.93%`)
- **Isolated Nodes (Degree = 0)**: `64` (`3.07%`)
- **Average Node Degree**: `19.55`
- **Maximum Node Degree**: `524` (Hub entities such as core techniques/malware)

---

## E. MITRE ATT&CK Structural Integrity

| MITRE Object Type | Total Count | Valid ID Count | Validity Ratio |
| :--- | :---: | :---: | :---: |
| **Technique** | 858 | 858 | **100.0%** |
| **Malware** | 733 | 733 | **100.0%** |
| **ThreatActor** | 191 | 191 | **100.0%** |
| **Campaign** | 56 | 56 | **100.0%** |

### Structural Hierarchy Relationships
- **`SUBTECHNIQUE_OF` Relationships**: `477`
- **`USES` Relationships**: `18555`
- **Dangling / Invalid Endpoint Edges**: `0` (0 detected)

---

## F. CVE/NVD Integrity
- **Total CVE Nodes**: `40`
- **CVEs with CVSS Score / Severity Properties**: `1` (2.5%)
- **CVEs with Affected Software Edges (`AFFECTS`)**: `20` (50.0%)
- **CVEs with Weakness Edges (`HAS_WEAKNESS`)**: `20` (50.0%)
- **CVEs Missing Metadata Properties**: `39`

---

## G. Provenance Analysis
- **Nodes with Provenance Identifiers (`stix_id` / `mitre_id` / `external_id` / `source`)**: `1987` (95.3%)
- **Nodes without Provenance Identifiers**: `98` (4.7%)
- **STIX Identifier Coverage**: `1987` nodes (95.3%)

---

## H. Temporal Metadata

| Temporal Field | Available Node Count | Coverage % | Description |
| :--- | :---: | :---: | :--- |
| `published` | 20 | 0.96% | CVE publication date |
| `last_modified` | 20 | 0.96% | NVD modification date |
| `modified` | 99 | 4.75% | STIX object modification timestamp |
| `last_synced` | 99 | 4.75% | TAXII relationship sync timestamp |
| `first_seen` | 0 | 0.0% | Not populated in current schema |
| `last_seen` | 0 | 0.0% | Not populated in current schema |

---

## I. STIX/TAXII Synchronization Scope
> [!NOTE]
> The current knowledge graph incorporates an **initial 100-object TAXII relationship synchronization** rather than a complete TAXII server repository clone. All STIX-compliant entities maintain full `stix_id` UUID mappings to ensure future TAXII updates align without schema collision.

---

## J. Limitations
1. **CVSS Property Population**: 39 out of 40 CVE nodes lack explicit CVSS score/severity properties, relying on relational links (`AFFECTS`, `HAS_WEAKNESS`) instead.
2. **Temporal Coverage**: Real-time event fields (`first_seen`, `last_seen`) are absent as the graph currently indexes structural threat intelligence rather than dynamic SIEM logs.
3. **Isolated Entity Nodes**: 64 nodes (3.07%) are unlinked hub artifacts from raw feed ingestion.

---

## K. Paper-Ready Summary
> *"The Member 2 Neo4j Knowledge Graph comprises 2,085 nodes and 20,382 relationships, exhibiting a 96.93% connected graph ratio and an average node degree of 19.55. MITRE ATT&CK structural integrity reaches 100.0% validity across all 858 Technique, 733 Malware, 191 ThreatActor, and 56 Campaign entities. Provenance tracking covers 95.30% of graph entities via STIX UUIDs and MITRE external IDs, establishing a verified structural baseline for hybrid retrieval without fabricated entity relationships."*
