from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session


from app.database.connection import get_db
from app.models.models import ClassifiedRecord
from app.security.authorization import can_access_record
from app.security.permissions import has_permission

router = APIRouter(
    prefix="/records",
    tags=["Classified Records"]
)


@router.get("/")
def get_records(db: Session = Depends(get_db)):
    records = (
        db.query(ClassifiedRecord)
        .filter(ClassifiedRecord.classification_status == "APPROVED")
        .all()
    )

    return [
        {
            "record_id": record.record_id,
            "record_code": record.record_code,
            "title": record.title,
            "description": record.description,
            "category_id": record.category_id,
            "clearance_id": record.clearance_id,
            "classification_status": record.classification_status,
            "created_by": record.created_by,
            "classified_by": record.classified_by,
            "classified_at": record.classified_at,
            "status": record.status
        }
        for record in records
    ]


@router.get("/{record_code}/access/{user_id}")
def test_record_access(
    record_code: str,
    user_id: int,
    db: Session = Depends(get_db)
):
    record = (
        db.query(ClassifiedRecord)
        .filter(ClassifiedRecord.record_code == record_code)
        .first()
    )

    if not record:
        return {
            "record_code": record_code,
            "access": "DENIED",
            "reason": "Record not found"
        }

    if not has_permission(
        db,
        user_id,
        "VIEW_RECORDS"
    ):
        return {
            "record_code": record_code,
            "user_id": user_id,
            "access": "DENIED",
            "reason": "Missing VIEW_RECORDS permission"
        }

    access_granted = can_access_record(
        db,
        user_id,
        record
    )

    if not access_granted:
        return {
            "record_code": record_code,
            "user_id": user_id,
            "access": "DENIED",
            "reason": "Insufficient authorization"
        }

    return {
        "record_code": record.record_code,
        "user_id": user_id,
        "access": "GRANTED",
        "title": record.title,
        "description": record.description,
        "record_content": record.record_content
    }