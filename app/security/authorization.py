from sqlalchemy.orm import Session

from app.models.models import User, ClassifiedRecord, ClearanceLevel


def can_access_record(
    db: Session,
    user_id: int,
    record: ClassifiedRecord
) -> bool:

    user = db.query(User).filter(
        User.user_id == user_id
    ).first()

    if not user:
        return False

    if user.account_status != "ACTIVE":
        return False

    if record.classification_status != "APPROVED":
        return False

    if user.clearance_id is None:
        return False

    if record.clearance_id is None:
        return False

    user_clearance = db.query(ClearanceLevel).filter(
        ClearanceLevel.clearance_id == user.clearance_id
    ).first()

    record_clearance = db.query(ClearanceLevel).filter(
        ClearanceLevel.clearance_id == record.clearance_id
    ).first()

    if not user_clearance:
        return False

    if not record_clearance:
        return False

    return (
        user_clearance.level_number
        >= record_clearance.level_number
    )