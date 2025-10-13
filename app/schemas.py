from pydantic import BaseModel
from typing import Optional

class CreateUserResponse(BaseModel):
    user: Optional[dict]
    access_token: str
    token_type: str

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