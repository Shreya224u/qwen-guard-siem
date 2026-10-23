import logging
from threading import Thread

from sqlalchemy import inspect, text

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

# Logging configuration
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

# Hide individual investigation INFO logs
logging.getLogger("siem.investigation").setLevel(logging.WARNING)

from app.config import settings
from app.db.postgres import engine, SessionLocal
from app.db.base import Base

# Import all models so SQLAlchemy registers them before create_all()
import app.db.model_registry  # noqa: F401 -- registers all SQLAlchemy models
from app.ml.models.user import User, UserRole
from app.models.log_entry import LogEntry
from app.api.v1.router import api_v1_router
from app.core.exceptions import unhandled_exception_handler
from app.core.security import get_password_hash, verify_password
from app.services import mitre_mapping_service


app = FastAPI(
    title="Next-Gen SIEM API",
    version="0.2.0",
)


# CORS Configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=list({
        settings.FRONTEND_URL.rstrip("/"),
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://localhost:5174",
    }),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(api_v1_router, prefix="/api/v1")
app.add_exception_handler(Exception, unhandled_exception_handler)


def _setup_graph_constraints():
    # Graph connectivity is optional and may involve a slow external TLS
    # handshake. Keep it out of the critical API startup path.
    try:
        from app.graph import graph_schema
        graph_schema.setup_constraints()
    except Exception:
        logging.getLogger("siem.graph").exception(
            "Neo4j constraint setup failed in the background"
        )


@app.on_event("startup")
def on_startup():
    """
    Initialize database tables and MITRE ATT&CK mappings.
    """

    # Create database tables.
    Base.metadata.create_all(bind=engine)

    # Upgrade databases created before log ownership was introduced.
    columns = {column["name"] for column in inspect(engine).get_columns("log_entries")}
    with engine.begin() as connection:
        oauth_state_columns = {column["name"] for column in inspect(engine).get_columns("oauth_states")}
        if "frontend_url" not in oauth_state_columns:
            connection.execute(text("ALTER TABLE oauth_states ADD COLUMN frontend_url VARCHAR(512)"))
        oauth_link_state_columns = {column["name"] for column in inspect(engine).get_columns("oauth_link_states")}
        if "frontend_url" not in oauth_link_state_columns:
            connection.execute(text("ALTER TABLE oauth_link_states ADD COLUMN frontend_url VARCHAR(512)"))
        if "user_id" not in columns:
            connection.execute(text("ALTER TABLE log_entries ADD COLUMN user_id INTEGER REFERENCES users(id)"))
        if "user_id" not in columns:
            connection.execute(text("CREATE INDEX IF NOT EXISTS ix_log_entries_user_id ON log_entries (user_id)"))
        user_columns = {column["name"] for column in inspect(engine).get_columns("users")}
        if "phone" not in user_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN phone VARCHAR(32)"))
        if "oauth_provider" not in user_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN oauth_provider VARCHAR(16)"))
        if "oauth_subject" not in user_columns:
            connection.execute(text("ALTER TABLE users ADD COLUMN oauth_subject VARCHAR(128)"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_phone ON users (phone)"))
        connection.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS ix_users_oauth_identity ON users (oauth_provider, oauth_subject)"))

    db = SessionLocal()
    try:
        # Create an initial administrator only when explicitly enabled and the
        # default sample password has been replaced in backend/.env.
        if settings.SEED_DEFAULT_USERS and settings.ADMIN_PASSWORD != "admin123":
            initial_admin = db.query(User).filter(User.username == settings.ADMIN_USERNAME).first()
            if initial_admin is None:
                db.add(User(
                    username=settings.ADMIN_USERNAME,
                    email=f"{settings.ADMIN_USERNAME}@localhost.invalid",
                    hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                    role=UserRole.admin,
                ))
            elif verify_password(settings.ADMIN_PASSWORD, initial_admin.hashed_password):
                # Promote only the account whose existing password matches the
                # operator-configured admin credential in backend/.env.
                initial_admin.role = UserRole.admin
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

    # Avoid adding model loading and first-use initialization to the first
    # upload's response time. Keep startup available if model warmup fails;
    # the prediction service can retry lazy loading when called.
    try:
        from app.ml.predict import warmup as warm_ml_models
        warm_ml_models()
        logging.getLogger("siem.startup").info(
            "ML prediction models loaded and ready"
        )
    except Exception:
        logging.getLogger("siem.startup").exception(
            "ML prediction model warmup failed; it will retry on first use"
        )

    Thread(target=_setup_graph_constraints, name="siem-graph-setup", daemon=True).start()


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
