

from pydantic import BaseModel
from typing import List, Dict, Any


class GraphHealthResponse(BaseModel):
    available: bool
    message: str


class GraphSyncResponse(BaseModel):
    alert_id: int
    synced: bool
    message: str


class GraphBackfillResponse(BaseModel):
    total_candidates: int
    synced: int
    failed: int
    skipped_graph_unavailable: bool


class GraphCorrelationResponse(BaseModel):
    query_type: str
    query_value: str
    count: int
    results: List[Dict[str, Any]]