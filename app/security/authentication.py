import bcrypt
from sqlalchemy.orm import Session

from app.models.models import User
from app.security.passwords import verify_password


# A process-local dummy hash keeps missing, inactive, and passwordless accounts
# on the same bcrypt verification path as an active account.
_DUMMY_PASSWORD_HASH = bcrypt.hashpw(
    b"not-a-real-user-password",
    bcrypt.gensalt(),
).decode("ascii")


def authenticate_user(
    db: Session,
    personnel_id: str,
    password: str
):

    user = db.query(User).filter(
        User.personnel_id == personnel_id
    ).first()

    if user is None:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return None

    if user.account_status != "ACTIVE" or not user.password_hash:
        verify_password(password, _DUMMY_PASSWORD_HASH)
        return None

    password_matches = verify_password(password, user.password_hash)
    if not password_matches:
        return None

    return user
