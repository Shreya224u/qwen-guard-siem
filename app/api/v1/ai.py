from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.ml.models.user import User
from app.services.ollama_service import analyze_security_events

router = APIRouter(prefix="/ai", tags=["AI Analysis"])


class SecurityAnalysisRequest(BaseModel):
    events: list[dict] = Field(min_length=1, max_length=30)


@router.post("/analyze")
def analyze_events(
    request: SecurityAnalysisRequest,
    current_user: User = Depends(get_current_user),
):
    return analyze_security_events(request.events)