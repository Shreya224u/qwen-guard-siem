from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user, require_admin
from app.models.alert import Alert
from app.models.log_entry import LogEntry
from app.ml.models.user import User
from app.schemas.graph import (
    GraphHealthResponse, GraphSyncResponse, GraphBackfillResponse, GraphCorrelationResponse
)

router = APIRouter(prefix="/graph", tags=["Graph"])


def _graph_services():
    # Neo4j's driver and TLS stack are only needed when a graph endpoint is
    # called, not while the rest of the API is importing.
    from app.graph import graph_client, graph_sync_service
    return graph_client, graph_sync_service


@router.get("/visualization")
def graph_visualization(current_user: User = Depends(get_current_user)):
    """Return graph nodes and relationships for the dashboard visualization."""
    graph_client, _ = _graph_services()
    rows = graph_client.run_read(
        """
        MATCH (n)
        OPTIONAL MATCH (n)-[r]->(m)
        RETURN elementId(n) AS node_id, labels(n) AS node_labels,
               properties(n) AS node_properties, elementId(m) AS target_id,
               labels(m) AS target_labels, properties(m) AS target_properties,
               type(r) AS relationship
        LIMIT 1000
        """
    )
    if rows is None:
        raise HTTPException(status_code=503, detail="Graph database unavailable")

    nodes = {}
    edges = {}

    def add_node(node_id, labels, properties):
        if not node_id:
            return
        labels = labels or ["Node"]
        properties = properties or {}
        kind = labels[0]
        value = next((properties.get(key) for key in (
            "address", "username", "name", "technique_id", "alert_id", "log_id"
        ) if properties.get(key) is not None), str(node_id))
        nodes[node_id] = {
            "id": node_id,
            "type": kind,
            "label": f"{kind}: {value}",
            "properties": properties,
        }

    for row in rows:
        add_node(row.get("node_id"), row.get("node_labels"), row.get("node_properties"))
        add_node(row.get("target_id"), row.get("target_labels"), row.get("target_properties"))
        if row.get("target_id") and row.get("relationship"):
            edge_key = (row["node_id"], row["target_id"], row["relationship"])
            edges[edge_key] = {
                "source": row["node_id"],
                "target": row["target_id"],
                "type": row["relationship"],
            }

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


@router.get("/health", response_model=GraphHealthResponse)
def graph_health(current_user: User = Depends(get_current_user)):
    graph_client, _ = _graph_services()
    available = graph_client.is_available()
    return GraphHealthResponse(
        available=available,
        message="Connected to Neo4j AuraDB" if available
        else "Neo4j unavailable — graph features inactive, rest of system unaffected",
    )


@router.post("/sync/{alert_id}", response_model=GraphSyncResponse)
def sync_alert(alert_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Manually sync one alert — for testing the graph pipeline in isolation."""
    _, graph_sync_service = _graph_services()
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    log = db.query(LogEntry).filter(LogEntry.id == alert.log_id).first()
    if not log:
        raise HTTPException(status_code=404, detail="Related log entry not found")

    synced = graph_sync_service.sync_alert_to_graph(alert, log)
    return GraphSyncResponse(
        alert_id=alert_id, synced=synced,
        message="Synced to graph" if synced else "Sync failed or Neo4j unavailable — check /graph/health",
    )


@router.post("/backfill", response_model=GraphBackfillResponse)
def backfill(db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    """
    Syncs every ALREADY-INVESTIGATED alert into the graph. Use this once
    after first enabling Neo4j, or to catch up alerts investigated while
    Neo4j was unreachable.
    """
    graph_client, graph_sync_service = _graph_services()
    if not graph_client.is_available():
        return GraphBackfillResponse(total_candidates=0, synced=0, failed=0, skipped_graph_unavailable=True)

    alerts = db.query(Alert).filter(Alert.investigated_at.isnot(None)).all()
    synced = 0
    failed = 0
    for alert in alerts:
        log = db.query(LogEntry).filter(LogEntry.id == alert.log_id).first()
        if not log:
            failed += 1
            continue
        if graph_sync_service.sync_alert_to_graph(alert, log):
            synced += 1
        else:
            failed += 1

    return GraphBackfillResponse(
        total_candidates=len(alerts), synced=synced, failed=failed, skipped_graph_unavailable=False
    )


@router.get("/correlation/ip/{ip}", response_model=GraphCorrelationResponse)
def correlation_by_ip(ip: str, current_user: User = Depends(get_current_user)):
    _, graph_sync_service = _graph_services()
    results = graph_sync_service.get_correlation_by_ip(ip)
    if results is None:
        raise HTTPException(status_code=503, detail="Graph database unavailable")
    return GraphCorrelationResponse(query_type="ip", query_value=ip, count=len(results), results=results)


@router.get("/correlation/user/{username}", response_model=GraphCorrelationResponse)
def correlation_by_user(username: str, current_user: User = Depends(get_current_user)):
    _, graph_sync_service = _graph_services()
    results = graph_sync_service.get_correlation_by_user(username)
    if results is None:
        raise HTTPException(status_code=503, detail="Graph database unavailable")
    return GraphCorrelationResponse(query_type="user", query_value=username, count=len(results), results=results)


@router.get("/correlation/device/{device}", response_model=GraphCorrelationResponse)
def correlation_by_device(device: str, current_user: User = Depends(get_current_user)):
    _, graph_sync_service = _graph_services()
    results = graph_sync_service.get_correlation_by_device(device)
    if results is None:
        raise HTTPException(status_code=503, detail="Graph database unavailable")
    return GraphCorrelationResponse(query_type="device", query_value=device, count=len(results), results=results)


@router.get("/correlation/technique/{technique_id}", response_model=GraphCorrelationResponse)
def correlation_by_technique(technique_id: str, current_user: User = Depends(get_current_user)):
    _, graph_sync_service = _graph_services()
    results = graph_sync_service.get_correlation_by_technique(technique_id)
    if results is None:
        raise HTTPException(status_code=503, detail="Graph database unavailable")
    return GraphCorrelationResponse(
        query_type="technique", query_value=technique_id, count=len(results), results=results
    )
