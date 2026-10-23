from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, LargeBinary, String, Text
from sqlalchemy.sql import func

from app.db.base import Base


class FeedbackSubmission(Base):
    __tablename__ = "feedback_submissions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String(120), nullable=True)
    email = Column(String(320), nullable=True)
    star_rating = Column(Integer, nullable=False)
    category = Column(String(40), nullable=False)
    visit_reason = Column(Text, nullable=False)
    found_what_needed = Column(String(20), nullable=False)
    comments = Column(Text, nullable=False)
    consent = Column(Boolean, nullable=False)
    attachment_name = Column(String(255), nullable=True)
    attachment_type = Column(String(120), nullable=True)
    attachment_data = Column(LargeBinary, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
