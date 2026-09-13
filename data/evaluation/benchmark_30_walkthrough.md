# 30-Query Retrieval Benchmark Walkthrough & Evaluation Report

**Evaluation Date**: 2026-09-13  
**Benchmark Expansion**: Expanded from original 10-query benchmark (Q01–Q10) to 30 queries (Q01–Q30).  
**Configuration**: Frozen Hybrid GraphRAG (ChromaDB VectorStore + Neo4j GraphRetriever + RRF Rank Fusion).

---

## 1. Query Selection & Ground Truth Establishment

### Selection Strategy
The 30 queries were curated to evaluate retrieval performance across the complete MITRE ATT&CK tactic landscape. 

- **Original Queries (Q01–Q10)**: Retained 100% unchanged to preserve historical continuity.
- **New Queries (Q11–Q30)**: Added 20 new natural language cybersecurity queries targeting diverse MITRE ATT&CK techniques.

### Ground Truth Verification
Ground truth was established **strictly from pre-indexed MITRE ATT&CK knowledge** in our normalized dataset and Neo4j graph (never from retrieval outputs):
- Verified that all 30 expected MITRE technique IDs exist in the Neo4j database (`t:Technique` nodes) and ChromaDB vector store collection (`cybersecurity_knowledge`).
- Each query maps to its authoritative MITRE ATT&CK ID (e.g. `T1047`, `T1547.001`, `T1548.002`, `T1027`, `T1110`, `T1021.001`, `T1113`, `T1071.001`, `T1485`).

---

## 2. MITRE ATT&CK Tactic Category Coverage

The 30 benchmark queries cover all core enterprise tactics:

| Tactic Category | Query IDs | Target MITRE Techniques Covered |
| :--- | :--- | :--- |
| **Execution** | Q01, Q02, Q10, Q11, Q12 | `T1059.001` (PowerShell), `T1059.003` (CMD), `T1059` (Command Interpreters), `T1047` (WMI), `T1569` (System Services) |
| **Defense Evasion / Process Injection** | Q03, Q17, Q18, Q19 | `T1055` (Process Injection), `T1027` (Obfuscation), `T1562.001` (Disable Tools), `T1036` (Masquerading) |
| **Credential Access** | Q04, Q20, Q21, Q22 | `T1003` (OS Credential Dumping), `T1110` (Brute Force), `T1555.003` (Browser Credentials), `T1003.001` (LSASS Memory) |
| **Initial Access / Phishing** | Q05 | `T1566` (Phishing) |
| **Persistence & Privilege Escalation** | Q06, Q09, Q13, Q14, Q15, Q16 | `T1078` (Valid Accounts), `T1053` (Scheduled Task/Job), `T1547.001` (Registry Run Keys), `T1543` (Create System Process), `T1548.003` (Sudo), `T1548.002` (UAC Bypass) |
| **Lateral Movement** | Q07, Q26, Q27 | `T1021` (Remote Services), `T1021.001` (RDP), `T1021.002` (SMB/Admin Shares) |
| **Ingress Tool Transfer** | Q08 | `T1105` (Ingress Tool Transfer) |
| **Discovery** | Q23, Q24, Q25 | `T1049` (Network Connections), `T1082` (System Info), `T1016` (Network Configuration) |
| **Collection** | Q28 | `T1113` (Screen Capture) |
| **Command and Control** | Q29 | `T1071.001` (Web Protocols) |
| **Impact** | Q30 | `T1485` (Data Destruction) |

---

## 3. Evaluation Methodology

Three frozen retrieval strategies were evaluated using standard information retrieval metrics at Top-K = 5:

1. **Vector**: Semantic dense retrieval using `all-MiniLM-L6-v2` embeddings in ChromaDB.
2. **Graph**: Lexical Cypher query matching against `Technique` node names and descriptions in Neo4j.
3. **Hybrid GraphRAG**: Pure Reciprocal Rank Fusion (RRF, $k=60$) combining vector and graph rankings, followed by 3-hop graph expansion.

### Calculated Metrics
- **Precision@5 (P@5)**: Ratio of relevant retrieved items in Top-5.
- **Recall@5 (R@5)**: Ratio of expected ground-truth items retrieved in Top-5.
- **MRR (Mean Reciprocal Rank)**: Multiplicative inverse of the rank of the first correct answer.
- **Latency (ms)**: Average end-to-end retrieval query execution latency.

---

## 4. Final Measured Results (30 Queries)

### Benchmark Summary Table

| Method | P@5 | R@5 | MRR | Latency(ms) |
| :--- | :---: | :---: | :---: | :---: |
| **Vector** | `0.1800` | `0.9000` | `0.6622` | `20.4` |
| **Graph** | `0.1600` | `0.8000` | `0.5972` | `175.7` |
| **Hybrid GraphRAG** | **`0.2000`** | **`1.0000`** | **`0.7928`** | `249.4` |

---

## 5. Relative Improvements of Hybrid GraphRAG

### Hybrid vs. Vector Baseline
- **Precision@5**: `0.2000 vs 0.1800` (**+11.11%** improvement)
- **Recall@5**: `1.0000 vs 0.9000` (**+11.11%** improvement)
- **MRR**: `0.7928 vs 0.6622` (**+19.72%** improvement)

### Hybrid vs. Graph Baseline
- **Precision@5**: `0.2000 vs 0.1600` (**+25.00%** improvement)
- **Recall@5**: `1.0000 vs 0.8000` (**+25.00%** improvement)
- **MRR**: `0.7928 vs 0.5972` (**+32.75%** improvement)

---

## 6. Limitations

1. **Top-K Capacity Bounding**: Single-ground-truth queries yield a theoretical maximum $P@5 = 0.2000$ when Top-K is fixed at 5.
2. **Expansion Latency**: Graph traversal adds ~229 ms latency over raw vector lookup due to multi-hop Cypher queries.
