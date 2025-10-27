from fastapi import APIRouter, Depends, HTTPException, Form, UploadFile, File
from typing import Optional
from sqlalchemy.orm import Session
from starlette import status
from app.database import get_db
from app.models import Users
from app.routes.auth import get_current_user
import io
import time
import cloudinary.uploader
import os
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from app.schemas import User

router = APIRouter(
    tags=["profile"]
)

ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')

bearer_scheme = HTTPBearer(
    description="Enter your Bearer token in the format: **Bearer &lt;token&gt;**"
)


@router.get("/me", response_model=User, summary="Get current user's profile")
async def get_my_profile(current_user: Users = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return current_user


@router.put(
    "/me",
    response_model=User,
    summary="Update current user's profile",
    description="Update your username, email, and optionally upload a new avatar image (multipart/form-data).",
    tags=["profile"],
)
async def update_my_profile(
    username: Optional[str] = Form(None),
    email: Optional[str] = Form(None),
    avatar: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: Users = Depends(get_current_user),
):
    # Check uniqueness for username/email if provided and different
    if username and username != current_user.username:
        exists = db.query(Users).filter(Users.username == username).first()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Username already in use")
        current_user.username = username

    if email and email != current_user.email:
        exists = db.query(Users).filter(Users.email == email).first()
        if exists:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Email already in use")
        current_user.email = email

    # Avatar upload (duck-typed check)
    if hasattr(avatar, 'filename') and hasattr(avatar, 'read') and avatar.filename:
        try:
            contents = await avatar.read()
            public_id = f"avatars/{current_user.username}_{int(time.time())}"
            result = cloudinary.uploader.upload(io.BytesIO(
                contents), public_id=public_id, resource_type='image', folder='fastapi_auth')
            avatar_url = result.get('secure_url')
            current_user.avatar = avatar_url
        except Exception as e:
            print(f"Error uploading avatar in profile update: {e}")
            raise HTTPException(
                status_code=500, detail="Failed to upload avatar")

    db.add(current_user)
    db.commit()
    db.refresh(current_user)
    return current_user
