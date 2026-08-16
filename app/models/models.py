from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String
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