from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.api.deps import get_db, get_current_user
from app.models.mitre_technique import MitreTechnique
from app.schemas.mitre import MitreTechniqueListResponse
from app.ml.models.user import User
from app.services.mitre_mapping_service import STATIC_MAPPING

router = APIRouter(prefix="/mitre", tags=["MITRE ATT&CK"])
VISIBLE_TECHNIQUE_IDS = {
    STATIC_MAPPING[event_type]["technique_id"]
    for event_type in list(STATIC_MAPPING)[:5]
}


@router.get("/techniques", response_model=MitreTechniqueListResponse)
def list_techniques(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Read-only reference list — useful for a frontend dropdown/legend later
    (Phase 8) and for verifying the seed data landed correctly.
    """
    rows = db.query(MitreTechnique).order_by(
        MitreTechnique.technique_id,
        MitreTechnique.id,
    ).all()
    # Older databases may contain repeated seed rows even though new installs
    # enforce a unique technique ID. Return one canonical row for each ID.
    unique = {}
    for row in rows:
        key = row.technique_id.strip().upper()
        if key in VISIBLE_TECHNIQUE_IDS:
            unique.setdefault(key, row)
    techniques = list(unique.values())
    return {"total": len(techniques), "techniques": techniques}
