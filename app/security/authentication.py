from sqlalchemy.orm import Session

from app.models.models import User
from app.security.passwords import verify_password


def authenticate_user(
    db: Session,
    personnel_id: str,
    password: str
):

    user = db.query(User).filter(
        User.personnel_id == personnel_id
    ).first()

    if not user:
        return None

    if user.account_status != "ACTIVE":
        return None

    if not user.password_hash:
        return None

    if not verify_password(password, user.password_hash):
        return None

    return user
