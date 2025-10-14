# FastAPI Authentication Service

A comprehensive and secure authentication API built with FastAPI. This project provides a robust foundation for user management, including standard JWT authentication, Google OAuth2, a secure password reset flow, rate limiting, and optional avatar uploads.

![Project Structure](https://i.imgur.com/your-image-url.png) ## ✨ Features

- **JWT Authentication**: Secure token-based login using username and password.
- **Google OAuth2**: Seamless "Sign in with Google" for both registration and login.
- **Secure Password Reset**: A complete forgot/reset password flow using email OTPs and Redis.
- **Rate Limiting**: Protects against brute-force attacks on login and password reset endpoints.
- **Optional Avatar Uploads**: Users can upload profile pictures to Cloudinary during registration.
- **Interactive API Docs**: Automatic, detailed API documentation with Swagger UI and ReDoc.
- **Cloud-Ready**: Designed to be deployed on serverless platforms like Vercel with a cloud database.

---

## 🚀 Getting Started

Follow these instructions to get a local copy up and running for development and testing.

### Prerequisites

You'll need accounts with the following services:
- **Python 3.9+**
- **Upstash**: For a serverless Redis instance (used for OTPs and rate limiting).
- **Google Cloud Platform**: To get OAuth2 Client ID and Secret.
- **Cloudinary**: For cloud-based image storage (avatars).
- **Gmail**: An account with an App Password to send emails.

### Installation & Setup

1.  **Clone the repository:**
    ```bash
    git clone <your-repository-url>
    cd fastapi-authentication
    ```

2.  **Create and activate a virtual environment:**
    ```bash
    python -m venv venv
    source venv/Scripts/activate  # On Windows
    # source venv/bin/activate    # On macOS/Linux
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure Environment Variables:**
    Create a `.env` file in the root directory and populate it with your credentials. See the **Environment Variables** section below for a complete list.

5.  **Run the application:**
    ```bash
    uvicorn main:app --reload
    ```
    The API will be available at `http://127.0.0.1:8000`.

---

## 📚 API Documentation

Once the server is running, you can access the interactive API documentation in your browser:

- **Swagger UI**: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
- **ReDoc**: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

These interfaces provide detailed information on all endpoints, including request/response models and allow for direct interaction with the API.

---

## 🔧 Environment Variables

[cite_start]Create a `.env` file in the project root and add the following variables with your own values[cite: 1]:

| Variable                  | Description                                                                 | Example Value                                              |
| ------------------------- | --------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `SQLALCHEMY_DATABASE_URL` | The connection string for your database (PostgreSQL recommended for production). | `postgresql://user:pass@host:port/db`                      |
| `CLOUDINARY_CLOUD_NAME`   | Your Cloudinary cloud name.                                                 | `your-cloud-name`                                          |
| `CLOUDINARY_API_KEY`      | Your Cloudinary API key.                                                    | `123456789012345`                                          |
| `CLOUDINARY_API_SECRET`   | Your Cloudinary API secret.                                                 | `a-very-secret-key`                                        |
| `SECRET_KEY`              | A secret key for signing JWTs.                                              | `a-long-random-secret-string`                              |
| `UPSTASH_REDIS_URL`       | The URL for your Upstash Redis database.                                    | `desired-teal-23465.upstash.io`                            |
| `UPSTASH_REDIS_TOKEN`     | The read/write token for your Upstash Redis database.                       | `AVupAAIncDIyZGVlYm...`                                    |
| `MAIL_USERNAME`           | The Gmail address used to send emails.                                      | `youremail@gmail.com`                                      |
| `MAIL_PASSWORD`           | The 16-character Google App Password for the email account.                 | `xxxx-xxxx-xxxx-xxxx`                                      |
| `MAIL_FROM`               | The "From" email address, usually the same as `MAIL_USERNAME`.              | `youremail@gmail.com`                                      |
| `MAIL_PORT`               | The SMTP port ( `465` for SSL, `587` for TLS).                               | `465`                                                      |
| `MAIL_SERVER`             | The SMTP server address.                                                    | `smtp.gmail.com`                                           |
| `MAIL_STARTTLS`           | Set to `True` for port 587, `False` for port 465.                           | `False`                                                    |
| `MAIL_SSL_TLS`            | Set to `True` for port 465, `False` for port 587.                           | `True`                                                     |
| `GOOGLE_CLIENT_ID`        | Your Google OAuth 2.0 Client ID.                                            | `12345...apps.googleusercontent.com`                       |
| `GOOGLE_CLIENT_SECRET`    | Your Google OAuth 2.0 Client Secret.                                        | `GOCSPX-abc...`                                            |
| `SESSION_SECRET_KEY`      | A secret key for signing session cookies (used by OAuth).                   | `another-long-random-secret-string`                        |
| `FRONTEND_CALLBACK_URL`   | The URL of your frontend application's page that handles the OAuth callback. | `http://localhost:3000/auth/callback`                      |