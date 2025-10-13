# Authentication Service — concise documentation

This repository implements a small Authentication API built with FastAPI. It supports:

- User registration (username/email/password) with optional avatar upload (Cloudinary).
- JWT-based authentication (password grant).
- Google OAuth2 login and exchange flow.
- Password reset via email + Redis-backed OTP.

This document is a concise reference with examples for local testing.

Quick start

1. Create and activate a Python venv (3.9+).
2. Install dependencies: `pip install -r requirements.txt`.
3. Copy `.env.example` to `.env` and fill values (DB URL, Redis, Cloudinary, Google, mail credentials).
4. Run: `uvicorn app.main:app --reload`.
5. Docs: `http://127.0.0.1:8000/docs` (Swagger UI).

## Endpoints

1. Register — POST /auth/register

- Content-Type: multipart/form-data
- Purpose: create user + optional avatar upload (file).

Request fields:

- username (string, required)
- email (string, required)
- password (string, required)
- avatar (file, optional)

Curl example:

```
curl -X POST "http://127.0.0.1:8000/auth/register" \
  -F "username=testuser" \
  -F "email=test@example.com" \
  -F "password=StrongPass123" \
  -F "avatar=@/path/to/avatar.jpg"
```

Success (201) example:

```
{
  "user": {"username":"testuser","email":"test@example.com","avatar":null},
  "access_token":"<jwt>",
  "token_type":"bearer"
}
```

2. Login (password) — POST /auth/token

- Content-Type: application/x-www-form-urlencoded
- Purpose: exchange username & password for a JWT

Form fields: `username`, `password`

Curl example:

```
curl -X POST "http://127.0.0.1:8000/auth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&password=StrongPass123"
```

Response:

```
{ "access_token": "<jwt>", "token_type": "bearer" }
```

3. Google OAuth2

- Start: GET /auth/login/google — redirects to Google's consent page.
- Callback (server): GET /auth/google — Google redirects here; server exchanges code for user info, creates or finds the user, stores a short-lived exchange code in Redis and redirects the browser to the frontend callback URL with `?code=<exchange_code>`.
- Frontend should POST that code to POST /auth/token/exchange to retrieve the final JWT.

Exchange example (frontend → backend):

```
POST /auth/token/exchange
{ "code": "<exchange_code>" }
```

Response:

```
{ "access_token": "<jwt>", "token_type": "bearer" }
```

4. Forgot password — POST /auth/forgot-password

- Accepts JSON or form-data: `{ "email": "user@example.com" }`.
- If the account exists the server generates an OTP, stores it in Redis (10m) and attempts to send it by email. For security, the endpoint always returns 200 to avoid account enumeration.

Curl (JSON):

```
curl -X POST "http://127.0.0.1:8000/auth/forgot-password" \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'
```

5. Reset password — POST /auth/reset-password

- Accepts JSON or form-data: `{ "email": "...", "otp": "123456", "new_password": "..." }`.
- Validates OTP against Redis and updates the user's password.

6. Exchange OAuth token — POST /auth/token/exchange

- Body: `{ "code": "<exchange_code>" }` (JSON)
- Returns: `{ "access_token": "<jwt>", "token_type": "bearer" }`

Environment variables (key ones)

- SQLALCHEMY_DATABASE_URL — database URL (sqlite example: sqlite:///./test.db)
- UPSTASH_REDIS_URL and UPSTASH_REDIS_TOKEN — Upstash credentials (or REDIS_URL for redis protocol)
- CLOUDINARY_CLOUD_NAME, CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET — Cloudinary upload
- GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET — Google OAuth credentials
- FRONTEND_CALLBACK_URL — frontend URL that receives the OAuth exchange code (e.g. http://localhost:3000/oauth/callback)
- MAIL_SERVER, MAIL_PORT, MAIL_USERNAME, MAIL_PASSWORD, MAIL_FROM — SMTP settings for sending OTPs
- MAIL_DEBUG=true (optional) — prints OTPs to console instead of sending email (dev)
- SESSION_SECRET_KEY, SECRET_KEY — app secrets

Local development notes

- Use `MAIL_DEBUG=true` while developing so OTPs are printed to console.
- The app exposes Swagger UI at `/docs` which can be used to exercise endpoints (multipart/form-data supported for file upload).
- Redis health check runs at startup and prints status.

Deployment

- A basic `vercel.json` is included for simple Vercel deployments. For production consider using a persistent DB (not SQLite), secure env vars via the hosting provider, and an appropriate hosting target (Render/Heroku/Fly) if you need long-running processes and lower latency.

Security notes

- Passwords are hashed (bcrypt) before storage. Bcrypt has a 72-byte limit — ensure long passwords are handled consistently in client/server.
- The password reset flow intentionally does not reveal whether an email is registered.
- Limit OTP requests per email/IP to avoid abuse (rate limiting is recommended; a basic limiter is included).

If you want I can:

- Add example responses for each error case to the docs
- Produce a short `README.md` with deployment steps for Vercel or Render
- Generate a Postman collection or OpenAPI client snippets

Done — this file is a concise, runnable reference. Want me to also commit a `README.md` and a Postman collection?
