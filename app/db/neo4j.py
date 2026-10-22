import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from neo4j import GraphDatabase

logger = logging.getLogger("siem.neo4j")

# Project root: SIEM-aiNew/
PROJECT_ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = PROJECT_ROOT / ".env"

load_dotenv(ENV_FILE, override=False)

# Use the same variable names as app/config.py
NEO4J_URI = os.getenv("NEO4J_URI", "neo4j://127.0.0.1:7687")
NEO4J_USERNAME = os.getenv(
    "NEO4J_USER",
    os.getenv("NEO4J_USERNAME", "neo4j"),
)
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "")
DATABASE = os.getenv("NEO4J_DATABASE", "neo4j")

if not NEO4J_PASSWORD:
    raise RuntimeError(
        f"NEO4J_PASSWORD is missing. Check your environment file: {ENV_FILE}"
    )

driver = GraphDatabase.driver(
    NEO4J_URI,
    auth=(NEO4J_USERNAME, NEO4J_PASSWORD),
)


def verify_neo4j_connection():
    """Verify connectivity to the local Neo4j database."""
    driver.verify_connectivity()
    logger.info("Connected to Neo4j successfully!")


def close_neo4j_connection():
    """Close the Neo4j driver."""
    driver.close()