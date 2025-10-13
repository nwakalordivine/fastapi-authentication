# Vercel entrypoint — re-export the FastAPI app
# Vercel will deploy this as a serverless function. It needs an `app` variable.
from app.main import app

# Ensure name `app` is present at module level
__all__ = ["app"]
