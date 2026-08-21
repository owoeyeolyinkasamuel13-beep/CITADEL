from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True)
    personnel_id = Column(String(20), unique=True, nullable=False)
    first_name = Column(String(50), nullable=False)
    last_name = Column(String(50), nullable=False)
    email = Column(String(100), unique=True, nullable=False)

    role_id = Column(Integer, ForeignKey("roles.role_id"), nullable=False)
    department_id = Column(Integer, ForeignKey("departments.department_id"), nullable=False)
    clearance_id = Column(Integer, ForeignKey("clearance_levels.clearance_id"), nullable=False)

    account_status = Column(String(30), nullable=False)
    mfa_enabled = Column(Boolean, nullable=False, default=False)

    password_hash = Column(String(255), nullable=True)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)


class ClearanceLevel(Base):
    __tablename__ = "clearance_levels"

    clearance_id = Column(Integer, primary_key=True)
    level_number = Column(Integer, nullable=False)
    classification_name = Column(String(100), nullable=False)

class ClassifiedRecord(Base):
    __tablename__ = "classified_records"

    record_id = Column(Integer, primary_key=True)
    record_code = Column(String(30), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    record_content = Column(Text, nullable=False)

    category_id = Column(
        Integer,
        ForeignKey("record_categories.category_id"),
        nullable=False
    )

    clearance_id = Column(
        Integer,
        ForeignKey("clearance_levels.clearance_id"),
        nullable=True
    )

    created_by = Column(
        Integer,
        ForeignKey("users.user_id"),
        nullable=False
    )

    classification_status = Column(String(30), nullable=False)
    classified_by = Column(
        Integer,
        ForeignKey("users.user_id"),
        nullable=True
    )

    classified_at = Column(DateTime, nullable=True)

    status = Column(String(30), nullable=False)
    created_at = Column(DateTime)
    updated_at = Column(DateTime)

