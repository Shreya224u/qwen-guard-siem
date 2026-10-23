"""
Syncs an investigated Alert — plus its triggering Event, IP, User, Device,
and MITRE mapping — into Neo4j as a small connected subgraph, and provides
correlation queries across the accumulated graph.

RELATIONSHIPS BUILT:
    (IP)-[:GENERATED]->(Event)
    (User)-[:PERFORMED]->(Event)
    (Device)-[:INVOLVED_IN]->(Event)
    (Event)-[:TRIGGERED]->(Alert)
    (Alert)-[:MAPPED_TO]->(MitreTechnique)
    (MitreTechnique)-[:BELONGS_TO]->(MitreTactic)

Every optional node (IP/User/Device/MITRE) is only included in the query
if the underlying data actually exists and is meaningful — e.g. we skip
creating a User node for username "unknown", since a generic placeholder
node would falsely link together every anonymous event ever seen.

BEST-EFFORT: every public function returns a safe default (False/None) if
Neo4j is unreachable. Called from alert_investigation_service AFTER the
PostgreSQL commit already succeeded — a failed graph sync means one alert
is missing from the graph, never that the alert itself is lost.
"""
import logging
from typing import Optional, List, Dict, Any

from app.graph import graph_client
from app.models.alert import Alert
from app.models.log_entry import LogEntry

logger = logging.getLogger("siem.graph")


def _build_sync_query(has_ip: bool, has_user: bool, has_device: bool, has_mitre: bool) -> str:
    lines = [
        "MERGE (e:Event {log_id: $log_id})",
        "SET e.event_type = $event_type, e.severity = $event_severity, "
        "e.timestamp = $timestamp, e.source_platform = $source_platform",
        "MERGE (a:Alert {alert_id: $alert_id})",
        "SET a.alert_type = $alert_type, a.severity = $alert_severity, "
        "a.status = $status, a.confidence_score = $confidence_score, a.risk_score = $risk_score",
        "MERGE (e)-[:TRIGGERED]->(a)",
    ]
    if has_ip:
        lines += ["MERGE (ip:IP {address: $ip_address})", "MERGE (ip)-[:GENERATED]->(e)"]
    if has_user:
        lines += ["MERGE (u:User {username: $username})", "MERGE (u)-[:PERFORMED]->(e)"]
    if has_device:
        lines += ["MERGE (d:Device {name: $device})", "MERGE (d)-[:INVOLVED_IN]->(e)"]
    if has_mitre:
        lines += [
            "MERGE (t:MitreTechnique {technique_id: $technique_id})",
            "SET t.name = $technique_name",
            "MERGE (tac:MitreTactic {name: $tactic})",
            "MERGE (t)-[:BELONGS_TO]->(tac)",
            "MERGE (a)-[:MAPPED_TO]->(t)",
        ]
    return "\n".join(lines)


def sync_alert_to_graph(alert: Alert, log: LogEntry) -> bool:
    if not graph_client.is_available():
        return False

    has_ip = bool(log.ip_address) and log.ip_address != "0.0.0.0"
    has_user = bool(log.username) and log.username != "unknown"
    has_device = bool(log.device)
    has_mitre = bool(alert.mitre_technique_id)

    query = _build_sync_query(has_ip, has_user, has_device, has_mitre)

    params: Dict[str, Any] = {
        "log_id": log.id,
        "event_type": log.event_type,
        "event_severity": log.severity,
        "timestamp": log.timestamp.isoformat() if log.timestamp else None,
        "source_platform": log.platform,
        "alert_id": alert.id,
        "alert_type": alert.alert_type,
        "alert_severity": alert.severity,
        "status": alert.status,
        "confidence_score": alert.confidence_score,
        "risk_score": alert.risk_score,
    }
    if has_ip:
        params["ip_address"] = log.ip_address
    if has_user:
        params["username"] = log.username
    if has_device:
        params["device"] = log.device
    if has_mitre:
        params["technique_id"] = alert.mitre_technique_id
        params["technique_name"] = alert.mitre_technique_name
        params["tactic"] = alert.mitre_tactic

    ok = graph_client.run_write(query, params)
    if not ok:
     logger.warning(
        f"Alert {alert.id} graph sync failed or skipped (Neo4j unavailable)."
    )

    return ok

# ── Correlation queries ─────────────────────────────────────────────
# All follow the same shape: find events tied to a shared entity, walk to
# their alerts, and (optionally) the MITRE technique each was mapped to.

_CORRELATION_FIELDS = """
    RETURN a.alert_id AS alert_id, a.alert_type AS alert_type, a.severity AS severity,
           a.status AS status, e.event_type AS event_type, e.timestamp AS timestamp,
           t.technique_id AS technique_id, t.name AS technique_name
    ORDER BY e.timestamp DESC
"""


def get_correlation_by_ip(ip: str) -> Optional[List[Dict[str, Any]]]:
    query = f"""
    MATCH (ip:IP {{address: $ip}})-[:GENERATED]->(e:Event)-[:TRIGGERED]->(a:Alert)
    OPTIONAL MATCH (a)-[:MAPPED_TO]->(t:MitreTechnique)
    {_CORRELATION_FIELDS}
    """
    return graph_client.run_read(query, {"ip": ip})


def get_correlation_by_user(username: str) -> Optional[List[Dict[str, Any]]]:
    query = f"""
    MATCH (u:User {{username: $username}})-[:PERFORMED]->(e:Event)-[:TRIGGERED]->(a:Alert)
    OPTIONAL MATCH (a)-[:MAPPED_TO]->(t:MitreTechnique)
    {_CORRELATION_FIELDS}
    """
    return graph_client.run_read(query, {"username": username})


def get_correlation_by_device(device: str) -> Optional[List[Dict[str, Any]]]:
    query = f"""
    MATCH (d:Device {{name: $device}})-[:INVOLVED_IN]->(e:Event)-[:TRIGGERED]->(a:Alert)
    OPTIONAL MATCH (a)-[:MAPPED_TO]->(t:MitreTechnique)
    {_CORRELATION_FIELDS}
    """
    return graph_client.run_read(query, {"device": device})


def get_correlation_by_technique(technique_id: str) -> Optional[List[Dict[str, Any]]]:
    query = """
    MATCH (t:MitreTechnique {technique_id: $technique_id})<-[:MAPPED_TO]-(a:Alert)<-[:TRIGGERED]-(e:Event)
    OPTIONAL MATCH (ip:IP)-[:GENERATED]->(e)
    RETURN a.alert_id AS alert_id, a.alert_type AS alert_type, a.severity AS severity,
           a.status AS status, e.event_type AS event_type, e.timestamp AS timestamp,
           ip.address AS ip_address
    ORDER BY e.timestamp DESC
    """
    return graph_client.run_read(query, {"technique_id": technique_id})