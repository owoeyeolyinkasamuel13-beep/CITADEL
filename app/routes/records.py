from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session


from app.database.connection import get_db
from app.models.models import ClassifiedRecord, User
from app.security.authorization import can_access_record
from app.security.permissions import has_permission
from app.security.tokens import get_current_user

router = APIRouter(
    prefix="/records",
    tags=["Classified Records"]
)


@router.get("/")
def get_records(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not has_permission(db, current_user.user_id, "VIEW_RECORDS"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient permissions",
        )

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
        if can_access_record(db, current_user.user_id, record)
    ]


@router.get("/{record_code}/access")
def test_record_access(
    record_code: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not has_permission(
        db,
        current_user.user_id,
        "VIEW_RECORDS"
    ):
        return JSONResponse(
            status_code=status.HTTP_403_FORBIDDEN,
            content={
                "access": "DENIED",
                "reason": "Insufficient authorization",
            },
        )

    record = (
        db.query(ClassifiedRecord)
        .filter(ClassifiedRecord.record_code == record_code)
        .first()
    )

    if not record:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"access": "DENIED", "reason": "Record not found"},
        )

    access_granted = can_access_record(
        db,
        current_user.user_id,
        record
    )

    if not access_granted:
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content={"access": "DENIED", "reason": "Record not found"},
        )

    return {
        "record_code": record.record_code,
        "user_id": current_user.user_id,
        "access": "GRANTED",
        "title": record.title,
        "description": record.description,
        "record_content": record.record_content
    }
