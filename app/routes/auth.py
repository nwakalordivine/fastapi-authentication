from datetime import timedelta, datetime
from typing import Optional, Union
import os
import io
import time
from fastapi import APIRouter, Depends, HTTPException, Form, UploadFile, File, Request
from sqlalchemy.orm import Session
from starlette import status
from app.database import get_db
from app.models import Users, UserPasswordsSet
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer, HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from app.schemas import Token, CreateUserResponse, TokenExchangeRequest, ForgotPasswordRequest, ResetPasswordRequest
from app.utils.redis_client import redis_client
from app.utils.email_helper import generate_otp, send_otp_email
from authlib.integrations.starlette_client import OAuth
from starlette.config import Config
import cloudinary
import cloudinary.uploader
import uuid
from starlette.responses import RedirectResponse
from app.utils.rate_limiter import (
    check_forgot_password_limit,
    is_login_blocked,
    record_failed_login_attempt,
    clear_failed_login_attempts
)

router = APIRouter(
    prefix='/auth',
)


SECRET_KEY = os.getenv('SECRET_KEY', 'change-me')
ALGORITHM = os.getenv('JWT_ALGORITHM', 'HS256')
ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.getenv('ACCESS_TOKEN_EXPIRE_MINUTES', '60'))

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/auth/token')
bearer_scheme = HTTPBearer(
    description="Enter your Bearer token in the format: **Bearer &lt;token&gt;**"
)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return bcrypt_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme), db: Session = Depends(get_db)):
    """
    Decodes the JWT token from the Authorization header to get the current user.
    """
    token = credentials.credentials
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception

    user = db.query(Users).filter(Users.id == int(user_id)).first()
    if user is None:
        raise credentials_exception
    return user


async def get_current_admin_user(current_user: Users = Depends(get_current_user)):
    """
    Checks if the current user is an admin. If not, raises a 403 Forbidden error.
    This is a dependency for protecting admin-only routes.
    """
    if not current_user.is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="The user does not have administrative privileges"
        )
    return current_user


@router.post(
    '/register',
    status_code=status.HTTP_201_CREATED,
    response_model=CreateUserResponse,
    summary="Register a New User",
    description="Create a new user account with a username, email, and password. This endpoint expects `multipart/form-data`. Avatar upload is optional.",
    tags=["Auth"],
    responses={
        201: {
            "description": "User created successfully.",
            "content": {
                "application/json": {
                    "example": {
                        "user": {
                            "username": "newuser",
                            "email": "user@example.com",
                            "avatar": "http://res.cloudinary.com/..."
                        },
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        400: {
            "description": "Username or email already exists.",
            "content": {
                "application/json": {
                    "example": {"detail": "Username or email already exists"}
                }
            }
        }
    }
)
async def register(
    username: str = Form(
        ...,
        description="The desired username for the new account.",
        example="newuser"
    ),
    email: str = Form(
        ...,
        description="The email address for the new account.",
        example="user@example.com"
    ),
    password: str = Form(
        ...,
        description="The password for the new account.",
        example="a_strong_password"
    ),
    avatar: Optional[Union[UploadFile, str]] = File(
        None, description="An optional avatar image file to upload."),
    db: Session = Depends(get_db),
):
    existing = db.query(Users).filter(
        (Users.username == username) | (Users.email == email)).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Username or email already exists'
        )

    avatar_url = None

    if hasattr(avatar, 'filename') and hasattr(avatar, 'read') and avatar.filename:
        try:
            contents = await avatar.read()
            public_id = f"avatars/{username}_{int(time.time())}"
            result = cloudinary.uploader.upload(io.BytesIO(
                contents), public_id=public_id, resource_type='image', folder='fastapi_auth')
            avatar_url = result.get('secure_url')
        except Exception as e:
            print(f"Error during Cloudinary upload: {e}")
            raise HTTPException(
                status_code=500, detail=f'Failed uploading avatar: {e}')

    user = Users(
        username=username,
        email=email,
        hashed_password=get_password_hash(password),
        avatar=avatar_url,
    )

    db.add(user)
    db.commit()
    db.refresh(user)

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"user": user, "access_token": access_token, "token_type": "bearer"}


@router.post(
    '/token',
    response_model=Token,
    summary="Login for Access Token",
    description="Authenticate with a username and password to receive a JWT. This uses the standard OAuth2 password flow (`application/x-www-form-urlencoded`).",
    tags=['Auth'],
    responses={
        200: {
            "description": "Login successful.",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        401: {
            "description": "Authentication failed.",
            "content": {"application/json": {"example": {"detail": "Incorrect username or password"}}}
        },
        429: {
            "description": "Account locked due to too many failed attempts.",
            "content": {"application/json": {"example": {"detail": "Account is locked due to too many failed login attempts. Please try again in 24 hours."}}}
        }
    }
)
def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    if is_login_blocked(form_data.username):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Account is locked due to too many failed login attempts. Please try again in 24 hours.")
    user = db.query(Users).filter(Users.username == form_data.username).first()
    if user and user.is_blocked:
        return {"access_token": "None: this user is blocked", "token_type": "bearer"}
    if not user or not user.hashed_password or not verify_password(form_data.password, user.hashed_password):
        if user:
            record_failed_login_attempt(form_data.username)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail='Incorrect username or password')
    clear_failed_login_attempts(form_data.username)
    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}


@router.post(
    '/forgot-password',
    summary="Request a Password Reset",
    description="Initiates the password reset process. If an account with the provided email exists, a 6-digit OTP will be sent. Rate-limited to 3 requests per hour.",
    tags=['Auth'],
    responses={
        200: {
            "description": "Acknowledgement that the request was processed.",
            "content": {"application/json": {"example": {"message": "If an account with that email exists, a password reset code has been sent."}}}
        },
        429: {
            "description": "Rate limit exceeded for this email.",
            "content": {"application/json": {"example": {"detail": "You have made too many password reset requests. Please try again in an hour."}}}
        }
    }
)
async def forgot_password(request: ForgotPasswordRequest, db: Session = Depends(get_db)):
    if not check_forgot_password_limit(request.email):
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="You have made too many password reset requests. Please try again in an hour.")
    user = db.query(Users).filter(Users.email == request.email).first()
    if user:
        otp = generate_otp()
        redis_client.set(f"password_reset_{request.email}", otp, ex=600)
        await send_otp_email(request.email, otp)
    return {"message": "If an account with that email exists, a password reset code has been sent."}


@router.post(
    '/reset-password',
    summary="Reset Password with OTP",
    description="Completes the password reset. Provide the email, the received OTP, and the new password. The OTP is valid for 10 minutes.",
    tags=['Auth'],
    responses={
        200: {
            "description": "Password was reset successfully.",
            "content": {"application/json": {"example": {"message": "Password has been reset successfully."}}}
        },
        400: {
            "description": "OTP is incorrect or has expired.",
            "content": {"application/json": {"example": {"detail": "Invalid OTP."}}}
        }
    }
)
async def reset_password(request: ResetPasswordRequest, db: Session = Depends(get_db)):
    redis_key = f"password_reset_{request.email}"
    stored_otp = redis_client.get(redis_key)
    if not stored_otp or stored_otp != request.otp:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OTP.")
    user = db.query(Users).filter(Users.email == request.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    new_plain = request.new_password

    if user.hashed_password and verify_password(new_plain, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="New password must be different from the current password.")

    pass_set = db.query(UserPasswordsSet).filter(
        UserPasswordsSet.user_id == user.id).first()
    if pass_set and pass_set.old_hashed_password and verify_password(new_plain, pass_set.old_hashed_password):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="New password must be different from the previously used password.")

    current_hash = user.hashed_password
    if not pass_set:
        pass_set = UserPasswordsSet(
            user_id=user.id, old_hashed_password=current_hash)
        db.add(pass_set)
    else:
        pass_set.old_hashed_password = current_hash

    user.hashed_password = get_password_hash(new_plain)
    db.add(user)
    db.commit()
    db.refresh(user)

    redis_client.delete(redis_key)
    return {"message": "Password has been reset successfully."}

config = Config('.env')
oauth = OAuth(config)
oauth.register(name='google', server_metadata_url='https://accounts.google.com/.well-known/openid-configuration', client_id=os.getenv(
    'GOOGLE_CLIENT_ID'), client_secret=os.getenv('GOOGLE_CLIENT_SECRET'), client_kwargs={'scope': 'openid email profile'})


@router.get(
    '/login/google',
    summary="Initiate Google OAuth Login",
    description="Starts the Google OAuth2 flow. **How to Test:** This endpoint initiates a redirect. Do not use the 'Execute' button in Swagger UI. Instead, open this URL directly in your browser: `http://122.0.0.1:8000/auth/login/google`.",
    tags=["OAuth"],
    responses={
        302: {"description": "Redirects the user to the Google login page."}
    }
)
async def login_google(request: Request):
    redirect_uri = request.url_for('auth_google')
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get(
    '/google',
    summary="Google OAuth Callback",
    description="**Do not call directly.** This is the callback URL that Google redirects to after successful authentication.",
    include_in_schema=False
)
async def auth_google(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.google.authorize_access_token(request)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Could not validate credentials: {e}")
    user_info = token.get('userinfo')
    if not user_info:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Could not retrieve user info")

    def _get_or_create_google_user_and_token(info: dict, db_session: Session) -> str:
        google_id = info.get('sub')
        email = info.get('email')
        user = db_session.query(Users).filter(
            Users.google_id == google_id).first()
        if user and user.is_blocked:
            return {"access_token": "None: this user is blocked", "token_type": "bearer"}
        if user:
            return create_access_token(data={"sub": str(user.id)})
        user = db_session.query(Users).filter(Users.email == email).first()
        if user:
            user.google_id = google_id
            db_session.commit()
            db_session.refresh(user)
            return create_access_token(data={"sub": str(user.id)})
        new_user = Users(google_id=google_id, email=email, username=info.get(
            'name', email), avatar=info.get('picture'), hashed_password=None)
        db_session.add(new_user)
        db_session.commit()
        db_session.refresh(new_user)
        return create_access_token(data={"sub": str(new_user.id)})
    access_token = _get_or_create_google_user_and_token(user_info, db)
    exchange_code = str(uuid.uuid4())
    redis_client.set(f"oauth_exchange_{exchange_code}", access_token, ex=60)
    frontend_url = os.getenv("FRONTEND_CALLBACK_URL")
    if not frontend_url:
        raise HTTPException(
            status_code=500, detail="Frontend callback URL is not configured.")
    return RedirectResponse(url=f"{frontend_url}?code={exchange_code}")


@router.post(
    '/token/exchange',
    response_model=Token,
    summary="Exchange OAuth Code for JWT",
    description="Exchanges the single-use code from the OAuth callback for a final JWT. This is the last step in the OAuth flow.",
    tags=["OAuth"],
    responses={
        200: {
            "description": "Exchange successful.",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer"
                    }
                }
            }
        },
        400: {
            "description": "The exchange code is invalid or has expired.",
            "content": {"application/json": {"example": {"detail": "Invalid or expired exchange code."}}}
        }
    }
)
async def exchange_token(request: TokenExchangeRequest):
    redis_key = f"oauth_exchange_{request.code}"
    access_token = redis_client.get(redis_key)
    if not access_token:
        raise HTTPException(
            status_code=400, detail="Invalid or expired exchange code.")
    redis_client.delete(redis_key)
    return {"access_token": access_token, "token_type": "bearer"}
