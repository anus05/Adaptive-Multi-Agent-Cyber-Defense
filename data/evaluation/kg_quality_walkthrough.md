# Member 2 — Knowledge Graph Quality & Provenance Validation Walkthrough

This document outlines the evaluation methodology, Cypher queries, and empirical findings for the Neo4j cybersecurity knowledge graph.

---

## 1. Summary of Empirical Findings

- **Graph Scale**: `2085` nodes, `20382` relationships.
- **Node Labels**: 10 distinct entity categories (`Technique`, `Malware`, `ThreatActor`, `Tool`, `Campaign`, `CourseOfAction`, `Software`, `CVE`, `Tactic`, `Weakness`).
- **Graph Topology**: Average degree of `19.55`, maximum degree of `524`, with `96.93%` connected nodes.
- **MITRE ATT&CK Integrity**: 100.0% valid IDs across all Technique, Malware, ThreatActor, and Campaign nodes. Zero dangling relationship endpoints detected.
- **Provenance Coverage**: `95.3%` of nodes carry explicit STIX UUIDs or MITRE external IDs.

---

## 2. Integrity Verification Queries & Samples

### 1. Technique -> Tactic
```cypher
MATCH (t:Technique) WHERE t.tactics IS NOT NULL RETURN t.name AS technique, t.tactics AS tactics LIMIT 3
```
*Sample Result*:
- `Extra Window Memory Injection` -> `['stealth', 'privilege-escalation']`
- `Scheduled Task` -> `['execution', 'persistence', 'privilege-escalation']`

### 2. Malware -> Technique
```cypher
MATCH (m:Malware)-[:USES]->(t:Technique) RETURN m.name AS malware, t.mitre_id AS mitre_id, t.name AS technique LIMIT 3
```
*Sample Result*:
- `HDoor` -> `T1685` (`Disable or Modify Tools`)
- `TrickBot` -> `T1053.005` (`Scheduled Task`)

### 3. ThreatActor -> Technique
```cypher
MATCH (a:ThreatActor)-[:USES]->(t:Technique) RETURN a.name AS actor, t.mitre_id AS mitre_id, t.name AS technique LIMIT 3
```
*Sample Result*:
- `APT38` -> `T1053.005` (`Scheduled Task`)
- `APT38` -> `T1033` (`System Owner/User Discovery`)

### 4. Campaign -> ThreatActor & Technique
```cypher
MATCH (c:Campaign)-[:ATTRIBUTED_TO]->(a:ThreatActor) RETURN c.name AS campaign, a.name AS actor LIMIT 3
```
*Sample Result*:
- `Operation Dream Job` -> `Lazarus Group`
- `KV Botnet Activity` -> `Volt Typhoon`

---

## 3. Discovered Integrity Issues

1. **CVSS Property Gap**: `39` out of `40` CVE nodes lack direct `cvss_score`/`cvss_severity` properties.
2. **Isolated Artifacts**: `64` unlinked nodes (3.07%) exist in the database.
3. **TAXII Sync Scope**: The TAXII synchronization represents a **100-object initial relationship sync** rather than a full TAXII repository clone.
