from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.connection import get_db
from app.models.models import User
from app.security.permissions import has_permission
from app.security.tokens import get_current_user

router = APIRouter(
    prefix="/users",
    tags=["Users"]
)


@router.get("/")
def get_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not has_permission(db, current_user.user_id, "MANAGE_USERS"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

    users = db.query(User).all()

    return [
        {
            "user_id": user.user_id,
            "personnel_id": user.personnel_id,
            "full_name": f"{user.first_name} {user.last_name}",
            "email": user.email,
            "role_id": user.role_id,
            "department_id": user.department_id,
            "clearance_id": user.clearance_id,
            "account_status": user.account_status,
            "mfa_enabled": user.mfa_enabled
        }
        for user in users
    ]
