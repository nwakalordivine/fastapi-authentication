# app/utils/services.py
import os
import asyncio
from dotenv import load_dotenv
import random
import string
import ssl
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

load_dotenv()

MAIL_USERNAME = os.getenv("MAIL_USERNAME")
MAIL_PASSWORD = os.getenv("MAIL_PASSWORD")
MAIL_FROM = os.getenv("MAIL_FROM")
MAIL_PORT = int(os.getenv("MAIL_PORT") or 587)
MAIL_SERVER = os.getenv("MAIL_SERVER")
MAIL_STARTTLS = os.getenv("MAIL_STARTTLS", "True").lower() == "true"
MAIL_SSL_TLS = os.getenv("MAIL_SSL_TLS", "False").lower() == "true"

def generate_otp(length: int = 6) -> str:
    """Generate a random numeric OTP of a given length."""
    return "".join(random.choices(string.digits, k=length))

def _send_email_sync(to_email: str, subject: str, html_body: str):
    """Synchronous SMTP send; intended to be run in a thread."""
    if not MAIL_SERVER or not MAIL_FROM:
        raise RuntimeError("MAIL_SERVER and MAIL_FROM must be set in environment")

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = to_email
    msg.attach(MIMEText(html_body, "html"))

    if MAIL_SSL_TLS:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(MAIL_SERVER, MAIL_PORT, context=context) as server:
            if MAIL_USERNAME and MAIL_PASSWORD:
                server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_FROM, [to_email], msg.as_string())
    else:
        with smtplib.SMTP(MAIL_SERVER, MAIL_PORT) as server:
            if MAIL_STARTTLS:
                server.starttls()
            if MAIL_USERNAME and MAIL_PASSWORD:
                server.login(MAIL_USERNAME, MAIL_PASSWORD)
            server.sendmail(MAIL_FROM, [to_email], msg.as_string())


async def send_otp_email(email: str, otp: str):
    """Asynchronously send an OTP email by running synchronous SMTP code in a thread."""
    html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Poppins:wght@400;600&display=swap');
            body {{
                font-family: 'Poppins', Arial, sans-serif;
            }}
        </style>
        </head>
        <body style="margin: 0; padding: 0; background-color: #F7F7F7; font-family: 'Poppins', Arial, sans-serif;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                <tr>
                    <td style="padding: 20px 0;">
                        <table align="center" border="0" cellpadding="0" cellspacing="0" width="600" style="border-collapse: collapse; background-color: #ffffff; border-radius: 12px; box-shadow: 0 5px 15px rgba(0,0,0,0.05);">
                            <tr>
                                <td align="center" style="padding: 30px 20px; background-color: #004AAD; color: #ffffff; border-top-left-radius: 12px; border-top-right-radius: 12px;">
                                    <h1 style="margin: 0; font-size: 24px;">Password Reset Code</h1>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 40px 30px;">
                                    <p style="margin: 0 0 20px 0; font-size: 16px; color: #333333; line-height: 1.6;">Hello,</p>
                                    <p style="margin: 0 0 25px 0; font-size: 16px; color: #333333; line-height: 1.6;">We received a request to reset your password. Use the code below to proceed.</p>
                                    <div style="background-color: #F0F5FF; padding: 20px; text-align: center; border-radius: 8px;">
                                        <p style="margin: 0; font-size: 14px; color: #555555;">Your verification code is:</p>
                                        <p style="margin: 10px 0 0 0; font-size: 36px; font-weight: 600; color: #004AAD; letter-spacing: 4px;">
                                            {otp}
                                        </p>
                                    </div>
                                    <p style="margin: 25px 0 0 0; text-align: center; font-size: 14px; color: #888888;">This code is valid for 10 minutes.</p>
                                </td>
                            </tr>
                            <tr>
                                <td style="padding: 20px 30px; background-color: #F7F7F7; text-align: center; border-bottom-left-radius: 12px; border-bottom-right-radius: 12px;">
                                    <p style="margin: 0; font-size: 12px; color: #aaaaaa;">If you did not request a password reset, you can safely ignore this email.</p>
                                    <p style="margin: 10px 0 0 0; font-size: 12px; color: #aaaaaa;">&copy; 2025 Ejike's auth. All rights reserved.</p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
    """
    await asyncio.to_thread(
        _send_email_sync,
        to_email=email,
        subject="Your Password Reset Code",
        html_body=html
    )