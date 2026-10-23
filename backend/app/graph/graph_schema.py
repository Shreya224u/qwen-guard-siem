

"""
Uniqueness constraints — these are what make MERGE actually prevent
duplicates. Without a constraint, MERGE still works, but two events with
slightly different property sets could create two separate IP nodes for
the same address instead of reusing one.

IF NOT EXISTS makes this idempotent — safe to call on every app startup.
"""
import logging
from app.graph import graph_client

logger = logging.getLogger("siem.graph")

CONSTRAINTS = [
    "CREATE CONSTRAINT ip_address_unique IF NOT EXISTS FOR (n:IP) REQUIRE n.address IS UNIQUE",
    "CREATE CONSTRAINT user_username_unique IF NOT EXISTS FOR (n:User) REQUIRE n.username IS UNIQUE",
    "CREATE CONSTRAINT device_name_unique IF NOT EXISTS FOR (n:Device) REQUIRE n.name IS UNIQUE",
    "CREATE CONSTRAINT event_log_id_unique IF NOT EXISTS FOR (n:Event) REQUIRE n.log_id IS UNIQUE",
    "CREATE CONSTRAINT alert_id_unique IF NOT EXISTS FOR (n:Alert) REQUIRE n.alert_id IS UNIQUE",
    "CREATE CONSTRAINT technique_id_unique IF NOT EXISTS FOR (n:MitreTechnique) REQUIRE n.technique_id IS UNIQUE",
    "CREATE CONSTRAINT tactic_name_unique IF NOT EXISTS FOR (n:MitreTactic) REQUIRE n.name IS UNIQUE",
]


def setup_constraints() -> None:
    """
    Best-effort: if AuraDB isn't reachable at startup, this logs a warning
    and returns — the app keeps starting normally. Graph sync will simply
    no-op (via graph_client's own best-effort design) until Neo4j becomes
    reachable and this runs successfully on a future restart.
    """
    if not graph_client.is_available():
        logger.warning("Neo4j unavailable at startup — skipping constraint setup. Graph sync will no-op for now.")
        return

    for stmt in CONSTRAINTS:
        ok = graph_client.run_write(stmt)
        if not ok:
            logger.warning(f"Failed to apply constraint: {stmt}")

    logger.info("Neo4j constraints verified/created.")