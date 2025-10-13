# app/utils/rate_limiter.py
from app.utils.redis_client import redis_client

# Define constants for clarity
FORGOT_PASSWORD_LIMIT = 3
FORGOT_PASSWORD_PERIOD_HOURS = 1

LOGIN_ATTEMPT_LIMIT = 5
LOGIN_BLOCK_PERIOD_HOURS = 24


def check_forgot_password_limit(email: str) -> bool:
    """
    Checks if an email has exceeded the 'forgot password' request limit.
    Uses a simple counter with a fixed time window.

    Returns:
        bool: True if the request is allowed, False if it is rate-limited.
    """
    if not redis_client:
        return True # Fail open if Redis is not configured

    key = f"forgot_password_limit:{email}"
    period_seconds = FORGOT_PASSWORD_PERIOD_HOURS * 3600

    # INCR is atomic. It increments the key and returns the new value.
    request_count = redis_client.incr(key)

    # If this is the first request in the time window, set the expiration.
    if request_count == 1:
        redis_client.expire(key, period_seconds)

    return request_count <= FORGOT_PASSWORD_LIMIT


def is_login_blocked(username: str) -> bool:
    """
    Checks if a username is currently blocked from logging in.

    Returns:
        bool: True if the user is blocked, False otherwise.
    """
    if not redis_client:
        return False # Fail open if Redis is not configured

    block_key = f"login_blocked:{username}"
    return redis_client.exists(block_key) > 0


def record_failed_login_attempt(username: str):
    """
    Records a failed login attempt and blocks the user if they exceed the limit.
    """
    if not redis_client:
        return

    attempts_key = f"login_attempts:{username}"
    block_key = f"login_blocked:{username}"
    block_duration_seconds = LOGIN_BLOCK_PERIOD_HOURS * 3600

    failed_attempts = redis_client.incr(attempts_key)

    if failed_attempts == 1:
        redis_client.expire(attempts_key, block_duration_seconds)

    if failed_attempts >= LOGIN_ATTEMPT_LIMIT:
        redis_client.set(block_key, "blocked", ex=block_duration_seconds)
        redis_client.delete(attempts_key)


def clear_failed_login_attempts(username: str):
    """
    Clears the failed login attempt counter for a user upon successful login.
    """
    if not redis_client:
        return 
        
    attempts_key = f"login_attempts:{username}"
    redis_client.delete(attempts_key)