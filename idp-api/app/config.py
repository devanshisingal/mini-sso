"""
Application Configuration settings loaded from environment variables using Pydantic Settings.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    APP_NAME: str = "Mini SSO Login Service"
    ENVIRONMENT: str = "development"
    DEBUG: bool = False

    # URLs
    ISSUER_URL: str = "http://localhost:8000"
    IDP_UI_URL: str = "http://localhost:5173"
    DEMO_APP_URL: str = "http://localhost:5174"

    # Database: SQLite for lightweight dev/tests, PostgreSQL for containerized/production
    DATABASE_URL: str = "sqlite:///./mini_sso.db"

    # Cryptography & Secrets
    SECRET_ENCRYPTION_KEY: str = "mini-sso-master-secret-key-32b-length-at-least"

    # Session & Tokens
    SESSION_COOKIE_NAME: str = "mini_sso_session"
    SESSION_MAX_AGE_SECONDS: int = 86400  # 24 hours
    COOKIE_SECURE: bool = False  # Set to True in production HTTPS
    COOKIE_SAMESITE: str = "lax"

    AUTH_CODE_LIFETIME_SECONDS: int = 60  # Codes expire in 60 seconds
    ACCESS_TOKEN_LIFETIME_SECONDS: int = 900  # 15 minutes
    ID_TOKEN_LIFETIME_SECONDS: int = 3600  # 1 hour

    # Security & Admin Policy
    ADMIN_EMAIL: str = "admin@example.com"
    ALLOW_OPEN_REGISTRATION: bool = True

    # CORS
    CORS_ALLOWED_ORIGINS: list[str] = [
        "http://localhost:3000",
        "http://localhost:3001",
        "http://localhost:5173",
        "http://localhost:5174",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:3001",
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
    ]


settings = Settings()
