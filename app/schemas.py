from pydantic import BaseModel
from typing import Optional


class Token(BaseModel):
    access_token: str
    token_type: str
    
class ForgotPasswordRequest(BaseModel):
    email: str

class ResetPasswordRequest(BaseModel):
    email: str
    otp: str
    new_password: str

class TokenExchangeRequest(BaseModel):
    code: str

class UserBase(BaseModel):
    username: str
    email: str
    avatar: Optional[str] = None
    is_admin: bool
    is_blocked: bool

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

    class Config:
        orm_mode = True

class CreateUserResponse(BaseModel):
    user: User
    access_token: str
    token_type: str

class UserUpdateRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None

class AdminBlock(BaseModel):
    user: User
    status: str