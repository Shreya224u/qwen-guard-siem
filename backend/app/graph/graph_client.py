

"""
Neo4j AuraDB connection layer.

Every function here is BEST-EFFORT:
if Neo4j is unreachable, misconfigured, or credentials are blank,
functions return a safe default (None/False) instead of raising.

Neo4j failure must never break the rest of the SIEM.

The SSL certificate configuration is handled automatically using
the certifi CA bundle, so the application does not require the
operator/developer to manually set SSL_CERT_FILE in PowerShell.
"""

import logging
import os
from typing import Optional, List, Dict, Any

import certifi
from neo4j import GraphDatabase, basic_auth

from app.config import settings


# ---------------------------------------------------------------------------
# Automatic SSL certificate configuration
# ---------------------------------------------------------------------------
# Neo4j AuraDB uses a secure TLS connection (neo4j+s://).
# On this Windows/Python environment, Python may not automatically locate
# the CA certificates required to verify the AuraDB certificate.
#
# certifi provides a maintained CA bundle.
#
# setdefault() means:
# - If SSL_CERT_FILE is already configured by the deployment environment,
#   we respect that configuration.
# - Otherwise, we automatically use certifi's CA bundle.
#
# This removes the need to manually run:
#   $env:SSL_CERT_FILE = ...
#
# before starting FastAPI.
os.environ.setdefault("SSL_CERT_FILE", certifi.where())


logger = logging.getLogger("siem.graph")

_driver = None
_driver_init_attempted = False

# AuraDB database name comes from .env / application settings.
AURA_DATABASE = settings.NEO4J_DATABASE


def get_driver():
    """
    Lazily creates and caches the Neo4j driver.

    Returns:
        Neo4j driver if connection succeeds.
        None if Neo4j is unavailable or misconfigured.

    This function never raises Neo4j connection errors to the rest
    of the application.
    """
    global _driver, _driver_init_attempted

    # Reuse an already-created driver.
    if _driver is not None:
        return _driver

    # Do not repeatedly attempt a known failed connection during
    # the same application lifetime.
    if _driver_init_attempted:
        return None

    _driver_init_attempted = True

    # Check that Neo4j configuration exists.
    if not (
        settings.NEO4J_URI
        and settings.NEO4J_USER
        and settings.NEO4J_PASSWORD
    ):
        logger.warning(
            "Neo4j credentials not configured (.env) — "
            "graph features disabled, everything else unaffected."
        )
        return None

    try:
        # Create the secure Neo4j AuraDB driver.
        #
        # The URI should remain:
        # neo4j+s://...
        #
        # SSL certificate verification remains enabled.
        # The CA bundle is configured automatically above using certifi.
        driver = GraphDatabase.driver(
            settings.NEO4J_URI,
            auth=basic_auth(
                settings.NEO4J_USER,
                settings.NEO4J_PASSWORD,
            ),
        )

        # Verify the connection immediately so that a bad connection
        # does not get stored as a working driver.
        driver.verify_connectivity()

        _driver = driver

        logger.info(
            "Connected to Neo4j AuraDB successfully."
        )

        return _driver

    except Exception:
        logger.warning(
            "Could not connect to Neo4j AuraDB — "
            "graph features disabled, everything else unaffected."
        )

        # Make sure a partially created driver is not retained.
        try:
            if "driver" in locals():
                driver.close()
        except Exception:
            pass

        return None


def is_available() -> bool:
    """
    Returns True if Neo4j is currently available.

    Returns False instead of raising if Neo4j is unavailable.
    """
    return get_driver() is not None


def run_write(
    query: str,
    params: Optional[Dict[str, Any]] = None,
) -> bool:
    """
    Executes a Neo4j write query.

    Returns:
        True  -> query executed successfully
        False -> Neo4j unavailable or query failed

    Never raises Neo4j errors to the application.
    """
    driver = get_driver()

    if driver is None:
        return False

    try:
        with driver.session(database=AURA_DATABASE) as session:
            session.run(query, params or {})

        return True

    except Exception:
        logger.exception(
            "Neo4j write failed — "
            "continuing without graph sync for this operation."
        )
        return False


def run_read(
    query: str,
    params: Optional[Dict[str, Any]] = None,
) -> Optional[List[Dict[str, Any]]]:
    """
    Executes a Neo4j read query.

    Returns:
        List of dictionaries on success.
        None if Neo4j is unavailable or the query fails.

    Never raises Neo4j errors to the application.
    """
    driver = get_driver()

    if driver is None:
        return None

    try:
        with driver.session(database=AURA_DATABASE) as session:
            result = session.run(query, params or {})

            return [
                record.data()
                for record in result
            ]

    except Exception:
        logger.exception(
            "Neo4j read failed."
        )
        return None


def close_driver() -> None:
    """
    Safely closes the cached Neo4j driver.

    Used when the application shuts down.
    """
    global _driver, _driver_init_attempted

    if _driver is not None:
        try:
            _driver.close()
        except Exception:
            logger.exception(
                "Error while closing Neo4j driver."
            )
        finally:
            _driver = None

    # Allow a fresh connection attempt if the application code
    # ever reuses this module after closing the driver.
    _driver_init_attempted = False
