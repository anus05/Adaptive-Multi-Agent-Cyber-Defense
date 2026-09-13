# Member 2 → Member 3 Integration Interface & LLM Reasoning Contract

This document defines the interface boundary between **Member 2 (GraphRAG Retrieval & Context Generation)** and **Member 3 (LLM Multi-Agent Reasoning & Orchestration)** in the Cyber Defense Threat Intelligence System.

---

## 1. System Architecture & End-to-End Data Flow

```text
User / SOC Alert / Query
          │
          ▼
   POST /api/graphrag/query  (FastAPI)
          │
          ▼
     GraphAgent  (graph/agent/graph_agent.py)
          │
          ▼
   Hybrid GraphRAG  (graph/retrieval/hybrid_retriever.py)
   (ChromaDB Semantic Vector Search + Neo4j Lexical Cypher Query)
          │
          ▼
   RRF Rank Fusion (Top-5 Fused Candidate Selection)
          │
          ▼
   Graph Expansion & Evidence Construction (Neo4j Neighbors & Multi-Hop Paths)
          │
          ▼
   Evidence Compressor (graph/agent/evidence_compressor.py)
          │
          ▼
   LLM Reasoner Interface Boundary (graph/agent/llm_reasoner.py)
          │
          ▼
Member 3 LLM Agents (Supervisor / Analyst / Response Agents)
```

---

## 2. Integration Boundaries & Responsibilities

### Member 2 Responsibilities
- **Knowledge Representation**: Maintains Neo4j ATT&CK Knowledge Graph and ChromaDB vector store.
- **Hybrid Retrieval**: Executes semantic vector search and lexical graph retrieval; computes Reciprocal Rank Fusion (RRF).
- **Graph Expansion**: Performs 3-hop graph relationship traversals and multi-hop attack path extractions for Top-5 techniques.
- **Context Preparation & Compression**: Formats structured evidence and text-compressed prompt contexts.
- **API Endpoint**: Exposes `POST /api/graphrag/query` returning complete JSON contexts.

### Member 3 Responsibilities
- **Agentic Orchestration**: Supervisor Agent, Detection Agent, Response Agent, SOC Analyst Agent workflows.
- **LLM Reasoning**: Invokes LLM provider (e.g. OpenAI / Gemini / Ollama) with Member 2's grounded prompt context.
- **Structured Response Generation**: Parses LLM output into Threat Intelligence reports.
- **Human-in-the-Loop Approval**: Manages user verification before triggering any defensive mitigation actions.

---

## 3. LLM Input Schema (Member 2 Output to Member 3)

The input contract provided to Member 3's LLM reasoning component is structured as follows:

```json
{
  "provider": "TO_BE_CONFIGURED",
  "model": "TO_BE_CONFIGURED",
  "system_prompt": "You are an evidence-grounded cybersecurity threat intelligence analyst...",
  "user_prompt": "CYBERSECURITY THREAT INTELLIGENCE ANALYSIS\n\nUSER QUERY:\n...",
  "query": "Which techniques are associated with command execution?",
  "source": "GraphAgent + Hybrid GraphRAG",
  "grounding": {
    "knowledge_graph": "Neo4j",
    "vector_database": "ChromaDB",
    "retrieval": "Hybrid GraphRAG",
    "evidence_compression": true
  },
  "statistics": {
    "vector_results": 5,
    "graph_entities": 5,
    "techniques": 5,
    "relationships": 20,
    "attack_paths": 10,
    "evidence_items": 198,
    "llm_context_characters": 4520
  }
}
```

### Prompt Context Structure (`user_prompt`)
The `user_prompt` field encapsulates:
1. **User Query**: Raw cybersecurity question or alert description.
2. **Grounding Source**: Declaration of Neo4j + ChromaDB evidence grounding.
3. **Retrieved Techniques**: Top-5 ATT&CK techniques with names, MITRE IDs, tactics, and compressed descriptions.
4. **Graph Relationships**: Direct outgoing and incoming STIX relationships (e.g. `SUBTECHNIQUE_OF`, `USES`, `BELONGS_TO`).
5. **Multi-Hop Attack Paths**: Multi-hop path sequences (up to 3 hops).
6. **Grounding Rules**: Strict instructions preventing hallucinations.

---

## 4. LLM Output Schema (Member 3 Reasoning Format)

Member 3's LLM reasoning component parses the model output into the following 8 standardized sections:

```json
{
  "threat_intelligence_summary": "High-level answer grounded strictly in retrieved evidence.",
  "relevant_mitre_techniques": [
    {
      "name": "Command and Scripting Interpreter",
      "mitre_id": "T1059",
      "relevance_explanation": "Direct match for executing commands across operating system platforms."
    }
  ],
  "graph_based_relationships": [
    {
      "source_entity": "Windows Command Shell",
      "relationship_type": "SUBTECHNIQUE_OF",
      "target_entity": "Command and Scripting Interpreter"
    }
  ],
  "attack_paths": [
    "Phishing (T1566) -> Command and Scripting Interpreter (T1059) -> Execution"
  ],
  "evidence_based_reasoning": "Deductions derived from RRF Top-5 consensus and verified Neo4j relationships.",
  "confidence": {
    "level": "HIGH",
    "justification": "Retrieved techniques show strong vector similarity (>0.75) and multiple supporting graph edges in Neo4j."
  },
  "evidence_limitations": "Retrieved evidence documents ATT&CK model capabilities; it does NOT establish that a live breach has occurred.",
  "defensive_considerations": [
    "Monitor command-line logging (Event ID 4688 / Sysmon Event ID 1).",
    "Restrict powershell.exe and cmd.exe execution policies where feasible."
  ]
}
```

---

## 5. Strict Grounding Rules

1. **Retrieved Knowledge vs. Observed Evidence**:
   - Knowledge in ATT&CK represents *possible attacker capabilities*, NOT confirmed telemetry from a live enterprise breach.
   - The LLM MUST NOT state that a technique was *observed* unless real telemetry/log evidence explicitly asserts an active incident.
2. **Distinguish Categories**:
   - **Retrieved Facts**: Explicit facts returned in the GraphRAG evidence array.
   - **Inferred Relationships**: Analytical deductions clearly demarcated as inference.
   - **Defensive Recommendations**: Suggested monitoring or mitigation strategies.
3. **No Hallucinated ATT&CK Entities**:
   - Techniques, IDs, tactics, and relationships must be derived strictly from the provided context.
4. **Insufficient Evidence Fallback**:
   - If evidence does not cover a user query, the LLM must explicitly state: *"Insufficient evidence retrieved to answer this query."*

---

## 6. FastAPI Endpoint (`POST /api/graphrag/query`)

### Request
```http
POST /api/graphrag/query HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{
  "query": "Which techniques are associated with command execution?"
}
```

### Response
```json
{
  "agent": "GraphAgent",
  "version": "1.0",
  "query": "Which techniques are associated with command execution?",
  "retrieval": {
    "strategy": "Hybrid GraphRAG",
    "vector_database": "ChromaDB",
    "knowledge_graph": "Neo4j",
    "vector_top_k": 5,
    "graph_expansion_hops": 3
  },
  "techniques": [
    {
      "name": "Command Obfuscation",
      "mitre_id": "T1027.010",
      "type": "attack-pattern",
      "description": "Adversaries may obfuscate content during command execution...",
      "retrieval_rank": 1,
      "distance": 0.7521
    }
  ],
  "relationships": [
    {
      "source": "Command Obfuscation",
      "relationship": "SUBTECHNIQUE_OF",
      "direction": "OUTGOING"
    }
  ],
  "attack_paths": [
    {
      "start_entity": "Command Obfuscation",
      "path": ["Command Obfuscation", "stealth"]
    }
  ],
  "evidence": [ ... ],
  "llm_context": "CYBERSECURITY GRAPHRAG EVIDENCE\nQuery: ...",
  "statistics": {
    "vector_results": 5,
    "graph_entities": 5,
    "techniques": 5,
    "relationships": 20,
    "attack_paths": 10,
    "evidence_items": 198,
    "llm_context_characters": 4520
  }
}
```
