from sqlalchemy.orm import Session

from app.models.models import User, Role, Permission


def has_permission(
    db: Session,
    user_id: int,
    permission_name: str
) -> bool:

    user = db.query(User).filter(
        User.user_id == user_id
    ).first()

    if not user:
        return False

    if user.account_status != "ACTIVE":
        return False

    role = db.query(Role).filter(
        Role.role_id == user.role_id
    ).first()

    if not role:
        return False

    permission = db.query(Permission).filter(
        Permission.permission_name == permission_name
    ).first()

    if not permission:
        return False

    return any(
        assigned_permission.permission_id == permission.permission_id
        for assigned_permission in role.permissions
    )