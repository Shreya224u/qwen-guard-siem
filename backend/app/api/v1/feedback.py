from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from app.api.deps import get_current_user, get_db
from app.ml.models.user import User
from app.models.feedback import FeedbackSubmission

router = APIRouter(prefix="/feedback", tags=["Feedback"])
MAX_ATTACHMENT_BYTES = 10 * 1024 * 1024
ALLOWED_CATEGORIES = {"Bug report", "Feature request", "Design/Usability", "General praise"}
ALLOWED_FOUND_ANSWERS = {"yes", "partially", "no"}


@router.post("")
async def submit_feedback(
    name: str = Form(default="", max_length=120),
    email: str = Form(default="", max_length=320),
    star_rating: int = Form(ge=1, le=5),
    category: str = Form(),
    visit_reason: str = Form(min_length=1, max_length=1200),
    found_what_needed: str = Form(),
    comments: str = Form(min_length=1, max_length=4000),
    consent: bool = Form(),
    attachment: UploadFile | None = File(default=None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if category not in ALLOWED_CATEGORIES:
        raise HTTPException(status_code=422, detail="Choose a valid feedback category.")
    if found_what_needed not in ALLOWED_FOUND_ANSWERS:
        raise HTTPException(status_code=422, detail="Choose a valid response.")
    if not consent:
        raise HTTPException(status_code=422, detail="Consent is required to submit feedback.")

    attachment_data = None
    attachment_name = None
    attachment_type = None
    if attachment and attachment.filename:
        attachment_type = attachment.content_type or ""
        if not (attachment_type.startswith("image/") or attachment_type.startswith("video/")):
            raise HTTPException(status_code=415, detail="Attachment must be an image or video.")
        attachment_data = await attachment.read(MAX_ATTACHMENT_BYTES + 1)
        if len(attachment_data) > MAX_ATTACHMENT_BYTES:
            raise HTTPException(status_code=413, detail="Attachment must be 10 MB or smaller.")
        attachment_name = attachment.filename[:255]

    item = FeedbackSubmission(
        user_id=current_user.id,
        name=name.strip() or None,
        email=email.strip().lower() or None,
        star_rating=star_rating,
        category=category,
        visit_reason=visit_reason.strip(),
        found_what_needed=found_what_needed,
        comments=comments.strip(),
        consent=consent,
        attachment_name=attachment_name,
        attachment_type=attachment_type,
        attachment_data=attachment_data,
    )
    db.add(item)
    db.commit()
    db.refresh(item)
    return {"feedback_id": item.id, "message": "Feedback submitted successfully."}
