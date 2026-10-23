"""Import ORM models once so SQLAlchemy registers all metadata tables."""

from app.ml.models.audit_log import AuditLog  # noqa: F401
from app.ml.models.user import User, UserRole  # noqa: F401
from app.models.account_security import AccountSecurity, SecuritySession  # noqa: F401
from app.models.alert import Alert  # noqa: F401
from app.models.auth_verification import AuthVerificationChallenge  # noqa: F401
from app.models.feedback import FeedbackSubmission  # noqa: F401
from app.models.log_entry import LogEntry  # noqa: F401
from app.models.mitre_technique import MitreTechnique  # noqa: F401
from app.models.oauth_identity import OAuthIdentity  # noqa: F401
from app.models.oauth_state import OAuthLinkState, OAuthState  # noqa: F401
