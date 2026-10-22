import logging

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Hide individual investigation INFO logs
logging.getLogger("siem.investigation").setLevel(logging.WARNING)

from app.db.postgres import engine, SessionLocal
from app.db.base import Base

# Import all models so SQLAlchemy registers them before create_all()
from app.ml.models.user import User, UserRole
from app.ml.models.audit_log import AuditLog
from app.models.log_entry import LogEntry
from app.models.alert import Alert
from app.models.mitre_technique import MitreTechnique

from app.api.v1 import auth, logs, alerts, ml, mitre, graph
from app.core.security import get_password_hash
from app.services import mitre_mapping_service
from app.graph import graph_schema
from app.api.v1 import ai


app = FastAPI(
    title="Next-Gen SIEM API",
    version="0.2.0",
)


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# API Routers
app.include_router(auth.router, prefix="/api/v1")
app.include_router(logs.router, prefix="/api/v1")
app.include_router(alerts.router, prefix="/api/v1")
app.include_router(ml.router, prefix="/api/v1")
app.include_router(mitre.router, prefix="/api/v1")
app.include_router(graph.router, prefix="/api/v1")
app.include_router(ai.router, prefix="/api/v1")


@app.on_event("startup")
def on_startup():
    """
    Initialize database tables, default users, and MITRE ATT&CK mappings.
    """

    # Create database tables.
    Base.metadata.create_all(bind=engine)

    db = SessionLocal()
    try:
        # Create default admin user
        if not db.query(User).filter(User.username == "admin").first():
            db.add(
                User(
                    username="admin",
                    email="admin@siem.local",
                    hashed_password=get_password_hash("admin123"),
                    role=UserRole.admin,
                )
            )

        # Create default analyst user
        if not db.query(User).filter(User.username == "analyst").first():
            db.add(
                User(
                    username="analyst",
                    email="analyst@siem.local",
                    hashed_password=get_password_hash("analyst123"),
                    role=UserRole.analyst,
                )
            )

        db.commit()

        # Seed the MITRE ATT&CK reference table and load the
        # in-memory mapping cache used by the Rule Engine and ML Engine.
        #
        # This is idempotent, so it is safe to execute on every startup.
        mitre_mapping_service.seed_mitre_techniques(db)
    except Exception:
        logging.getLogger("siem.startup").exception(
            "Database startup seeding failed unexpectedly"
        )
    finally:
        db.close()

    try:
        graph_schema.setup_constraints()
    except Exception:
        logging.getLogger("siem.graph").exception(
            "Neo4j constraint setup failed unexpectedly at startup"
        )


@app.get("/")
def root():
    return {
        "message": "Next-Gen SIEM API is running"
    }


@app.get("/health")
def health():
    return {
        "status": "ok"
    }