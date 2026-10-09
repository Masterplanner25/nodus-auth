from __future__ import annotations

from pydantic_settings import BaseSettings


class AuthSettings(BaseSettings):
    """Minimal auth configuration.  Reads from environment variables by default."""

    # 49 bytes. RFC 7518 §3.2 wants an HMAC key at least as long as the hash
    # output (32 for SHA-256), and the previous default was 31 -- one byte
    # under, which made PyJWT emit `InsecureKeyLengthWarning` on every call in
    # development. A warning that fires constantly on a value nobody is meant
    # to keep trains people to ignore the warning.
    SECRET_KEY: str = "dev-secret-change-in-production-not-for-real-use"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours

    model_config = {"env_prefix": "", "extra": "ignore"}
