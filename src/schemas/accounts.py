from pydantic import BaseModel, EmailStr, field_validator, Field, validator

from database import accounts_validators


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        if not any(c.isupper() for c in v):
            raise ValueError("Password must have an uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must have a digit")
        if not any(c in "!@#$%^&*" for c in v):
            raise ValueError("Password must have a special character")
        return v



class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    class Config:
        from_attributes = True


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str


class MessageResponseSchema(BaseModel):
    message: str

    class Config:
        from_attributes = True


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: str
    password: str = Field(..., min_length=8, max_length=64)


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    class Config:
        from_attributes = True


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str

class TokenRefreshResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

    class Config:
        from_attributes = True