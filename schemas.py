from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from datetime import date as date_type

# Base class for users
class UserBase(BaseModel):
    username: str
    email: EmailStr
    first_name: str
    last_name: str
    phone_number: Optional[str] = Field(None, pattern=r"^09\d{9}$")
    bio: Optional[str] = Field(None, max_length=500)
    date_of_birth: Optional[date_type] = None

    class Config:
        from_attributes = True

# Registration 
class UserCreate(UserBase):
    password: str = Field(..., min_length=8)
    password_confirm: str

    @field_validator('password')
    @classmethod
    def password_validation(cls, v):
        if v.isdigit():
            raise ValueError('رمز عبور نباید کاملاً عددی باشد')
        return v

# Login 
class UserLogin(BaseModel):
    username: str
    password: str

# Token 
class Token(BaseModel):
    access_token: str
    token_type: str

# Update Profile 
class UserUpdate(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    bio: Optional[str] = Field(None, max_length=500)
    phone_number: Optional[str] = Field(None, pattern=r"^09\d{9}$")
    date_of_birth: Optional[date_type] = None

# Change Password 
class ChangePassword(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=8)
    new_password_confirm: str

    @field_validator('new_password')
    @classmethod
    def password_not_numeric(cls, v):
        if v.isdigit():
            raise ValueError('رمز عبور جدید نباید کاملاً عددی باشد')
        return v

# Password Reset 
class ForgotPasswordRequest(BaseModel):
    email: EmailStr

class PasswordResetConfirm(BaseModel):
    email: EmailStr
    code: str
    new_password: str = Field(..., min_length=8)
    new_password_confirm: str
