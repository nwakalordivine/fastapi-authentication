# Authentication API Documentation

---
* **Base URL**: `https://fastapi-authentication.vercel.app`
---
## Register New User

* **URL**: `/auth/register`
* **Method**: `POST`
* **Content-Type**: `multipart/form-data`
* **Body (Form Fields)**:
    * `username` (string, required): A unique username for the new account.
    * `email` (string, required): The user's unique email address.
    * `password` (string, required): The user's password.
    * `avatar` (file, optional): An image file for the user's avatar.
* **Response**:
    **201: User created successfully**
    ```json
    {
        "user": {
            "username": "newuser",
            "email": "user@example.com",
            "avatar": "[http://res.cloudinary.com/](http://res.cloudinary.com/)..."
        },
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer"
    }
    ```
* **Errors**:
    * `400`: Username or email already exists.
    * `500`: Failed to upload avatar.

---
## Login for Access Token

* **URL**: `/auth/token`
* **Method**: `POST`
* **Content-Type**: `application/x-www-form-urlencoded`
* **Body (Form Fields)**:
    * `username` (string, required): The user's registered username.
    * `password` (string, required): The user's password.
* **Response**:
    **200: Login successful**
    ```json
    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer"
    }
    ```
* **Errors**:
    * `401`: Incorrect username or password.
    * `429`: Account locked due to too many failed login attempts.

---
## Request Password Reset (OTP)

* **URL**: `/auth/forgot-password`
* **Method**: `POST`
* **Content-Type**: `application/json`
* **Body**:
    ```json
    {
        "email": "user@example.com"
    }
    ```
* **Response**:
    **200: Request processed successfully**
    ```json
    {
        "message": "If an account with that email exists, a password reset code has been sent."
    }
    ```
* **Errors**:
    * `429`: Too many password reset requests for this email.

---
## Reset Password with OTP

* **URL**: `/auth/reset-password`
* **Method**: `POST`
* **Content-Type**: `application/json`
* **Body**:
    ```json
    {
        "email": "user@example.com",
        "otp": "123456",
        "new_password": "mynewsecurepassword"
    }
    ```
* **Response**:
    **200: Password reset successfully**
    ```json
    {
        "message": "Password has been reset successfully."
    }
    ```
* **Errors**:
    * `400`: OTP has expired or is invalid.
    * `404`: User not found.

---
## Initiate Google Login

* **URL**: `/auth/login/google`
* **Method**: `GET`
* **Description**: This endpoint is not a standard API call. It initiates the OAuth2 flow and must be opened in a web browser. The browser will be redirected to Google for authentication. Upon success, Google redirects back to your frontend with a `code` in the URL.
* **Response**:
    **302: Redirect**
    * The user's browser is redirected to `https://accounts.google.com/...`

---
## Exchange OAuth Code for JWT

* **URL**: `/auth/token/exchange`
* **Method**: `POST`
* **Content-Type**: `application/json`
* **Body**:
    ```json
    {
        "code": "PASTE_THE_CODE_FROM_THE_BROWSER_URL_HERE"
    }
    ```
* **Response**:
    **200: Exchange successful**
    ```json
    {
        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "token_type": "bearer"
    }
    ```
* **Errors**:
    * `400`: The exchange code is invalid or has expired.