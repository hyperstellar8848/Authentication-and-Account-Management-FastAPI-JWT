from sqlalchemy import Column, Integer, String, Boolean, Text, Date, DateTime, ForeignKey
from sqlalchemy.sql import func
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, nullable=False)
    email = Column(String, unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    first_name = Column(String, nullable=False)
    last_name = Column(String, nullable=False)
    bio = Column(Text, nullable=True) # Max 500 checked in Pydantic
    phone_number = Column(String, nullable=True) # Format checked in Pydantic
    date_of_birth = Column(Date, nullable=True)
    is_active = Column(Boolean, default=True)
    is_admin = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

class PasswordResetCode(Base):
    __tablename__ = "password_reset_codes"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    code = Column(String(6), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    is_used = Column(Boolean, default=False)
