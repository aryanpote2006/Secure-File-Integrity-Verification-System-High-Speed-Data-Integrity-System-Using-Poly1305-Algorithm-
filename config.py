import os
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-change-this-session-key")
    DATABASE = os.environ.get("DATABASE_URL", str(BASE_DIR / "instance" / "integrity.db"))
    UPLOAD_FOLDER = os.environ.get("UPLOAD_FOLDER", str(BASE_DIR / "instance" / "uploads"))
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    RESET_TOKEN_EXPIRY_MINUTES = 15
    RESET_REQUEST_COOLDOWN_SECONDS = 60
    MAIL_SENDER_NAME = os.environ.get("MAIL_SENDER_NAME", "Poly1305 Vault Security")
    MAIL_SENDER = os.environ.get("MAIL_SENDER", "security@poly1305-vault.local")
    SMTP_HOST = os.environ.get("SMTP_HOST")
    SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
    SMTP_USERNAME = os.environ.get("SMTP_USERNAME")
    SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD")
    SMTP_USE_TLS = os.environ.get("SMTP_USE_TLS", "true").lower() == "true"
    ALLOWED_EXTENSIONS = {
        "pdf", "doc", "docx", "txt", "zip", "png", "jpg", "jpeg", "gif", "webp",
        "csv", "xlsx", "pptx", "json", "xml", "md", "py", "java", "c", "cpp"
    }
