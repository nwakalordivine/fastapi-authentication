from fastapi import FastAPI
from app import models
from app.database import Base, engine
from app.routes import auth, admin, profile
from app.utils.redis_client import test_redis_connection
from starlette.middleware.sessions import SessionMiddleware
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(
    title="Authentication Service API",
    description="""
        A comprehensive Authentication API that supports:

        - **User Registration**: Create accounts with username, email, and password.
        - **JWT Authentication**: Standard token-based login.
        - **Google OAuth2**: Sign in and register with a Google account.
        - **Secure Password Reset**: A Forgot/Reset password flow using email and Redis.
        - **Rate Limiting**: Protection against brute-force attacks on login and password reset.
        - **Optional Avatar Uploads**: Users can upload profile pictures to Cloudinary.
    """,
    version="1.0.0",
)


def custom_openapi():
    if app.openapi_schema:
        return app.openapi_schema
    from fastapi.openapi.utils import get_openapi

    openapi_schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
    )

    try:
        token_path = openapi_schema['paths'].get('/auth/token')
        if token_path and 'post' in token_path:
            post_op = token_path['post']
            post_op['requestBody'] = {
                'content': {
                    'application/x-www-form-urlencoded': {
                        'schema': {
                            'type': 'object',
                            'properties': {
                                'username': {'type': 'string', 'example': 'alice'},
                                'password': {'type': 'string', 'format': 'password', 'example': 'hunter2'},
                            },
                            'required': ['username', 'password']
                        }
                    }
                },
                'required': True,
            }
    except Exception:
        pass

    app.openapi_schema = openapi_schema
    return app.openapi_schema


app.openapi = custom_openapi


app.add_middleware(
    SessionMiddleware,
    secret_key=os.getenv("SESSION_SECRET_KEY"),
    https_only=False,  # Set to True in production
    same_site="lax"
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(admin.router)
app.include_router(profile.router)

@app.get('/', tags=["Root"], summary="API Root")
def root():
    """Provides a simple welcome message for the API root."""
    return {"message": "Welcome to the Authentication Service API"}


@app.on_event("startup")
def on_startup():
    """Runs a Redis connection check when the application starts."""
    try:
        ok, msg = test_redis_connection()
    except Exception as e:
        print(f"Error during startup redis check: {e}")
