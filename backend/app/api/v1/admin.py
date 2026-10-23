from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.api.deps import get_db, require_admin
from app.ml.models.audit_log import AuditLog
from app.ml.models.user import User, UserRole
from app.schemas.auth import AuditLogOut, UserOut, UserRoleUpdate


router = APIRouter(prefix="/admin", tags=["Admin"])


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """List profile fields only; never return passwords or OAuth credentials."""
    return db.query(User).order_by(User.created_at.desc(), User.id.desc()).all()


@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_user_role(
    user_id: int,
    payload: UserRoleUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin),
):
    user = db.query(User).filter(User.id == user_id).with_for_update().first()
    if user is None:
        raise HTTPException(status_code=404, detail="User account not found.")
    if user.id == admin.id and payload.role != UserRole.admin:
        raise HTTPException(status_code=400, detail="You cannot remove your own administrator access.")
    if user.role == UserRole.admin and payload.role != UserRole.admin:
        admins = db.query(User).filter(User.role == UserRole.admin).count()
        if admins <= 1:
            raise HTTPException(status_code=400, detail="The last administrator cannot be demoted.")
    if user.role != payload.role:
        previous_role = user.role.value
        user.role = payload.role
        db.add(AuditLog(
            user=admin.username,
            action="user_role_changed",
            target=f"{user.username}:{previous_role}->{payload.role.value}",
        ))
        db.commit()
        db.refresh(user)
    return user


@router.get("/activity", response_model=list[AuditLogOut])
def list_activity(
    skip: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
):
    """Return recent user and administrative actions without sensitive credentials."""
    return (
        db.query(AuditLog)
        .order_by(AuditLog.timestamp.desc(), AuditLog.id.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
