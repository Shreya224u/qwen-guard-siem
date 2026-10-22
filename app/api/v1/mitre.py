from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.mitre_technique import MitreTechnique
from app.schemas.mitre import MitreTechniqueListResponse
from app.ml.models.user import User

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])


@router.get("/techniques", response_model=MitreTechniqueListResponse)
def list_techniques(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Read-only reference list — useful for a frontend dropdown/legend later
    (Phase 8) and for verifying the seed data landed correctly.
    """
    techniques = db.query(MitreTechnique).order_by(MitreTechnique.technique_id).all()
    return {"total": len(techniques), "techniques": techniques}