from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from graph.agent.graph_agent import GraphAgent


app = FastAPI(
    title="Cyber Defense Graph Intelligence API",
    description="Neo4j + GraphRAG API for cybersecurity threat intelligence",
    version="1.0.0"
)


# Initialize Graph Agent once when API starts
graph_agent = GraphAgent()


class GraphRAGRequest(BaseModel):
    query: str


@app.get("/")
def root():
    return {
        "service": "Cyber Defense Graph Intelligence API",
        "status": "running"
    }


@app.get("/health")
def health():
    return {
        "status": "healthy",
        "service": "graph-intelligence"
    }


@app.post("/api/graphrag/query")
def graphrag_query(request: GraphRAGRequest):

    if not request.query.strip():
        raise HTTPException(
            status_code=400,
            detail="Query cannot be empty"
        )

    try:
        result = graph_agent.analyze(request.query)

        return result

    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=str(e)
        )