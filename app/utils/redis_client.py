# app/utils/redis_client.py
from upstash_redis import Redis
import os
from dotenv import load_dotenv

load_dotenv()

# Expect UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN in .env. Be defensive: don't
# raise on import so the app can still start when env isn't configured; the
# startup test will print a clear message instead.
redis_url = os.getenv("UPSTASH_REDIS_URL")
redis_token = os.getenv("UPSTASH_REDIS_TOKEN")

redis_client = None
if redis_url and redis_token:
    try:
        redis_client = Redis(url=redis_url, token=redis_token)
    except Exception:
        # leave None and let the test function report details
        redis_client = None


def get_redis():
    return redis_client


def test_redis_connection():
    """Ping the Upstash client (or run a small set/get) and print a short
    message. Returns (ok: bool, message: str).
    """
    if redis_client is None:
        msg = "Redis client not configured (missing UPSTASH_REDIS_URL/UPSTASH_REDIS_TOKEN)"
        print(msg)
        return False, msg

    try:
        # upstash-redis supports ping(); if not, fall back to set/get
        try:
            pong = redis_client.ping()
            msg = f"Redis ping returned: {pong}"
            print(msg)
            return True, msg
        except AttributeError:
            # fallback: set and get a temporary key
            redis_client.set("__healthcheck__", "ok")
            val = redis_client.get("__healthcheck__")
            redis_client.delete("__healthcheck__")
            ok = (val == "ok") or (val == b"ok")
            msg = f"Redis set/get healthcheck returned: {val}"
            print(msg)
            return ok, msg
    except Exception as e:
        msg = f"Redis health check failed: {e}"
        print(msg)
        return False, msg
