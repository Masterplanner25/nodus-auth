from __future__ import annotations

from pydantic_settings import BaseSettings


class AuthSettings(BaseSettings):
    """Minimal auth configuration.  Reads from environment variables by default."""

    SECRET_KEY: str = "dev-secret-change-in-production"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    model_config = {"env_prefix": "", "extra": "ignore"}
