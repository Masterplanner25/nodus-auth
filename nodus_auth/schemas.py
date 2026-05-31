"""Auth request/response schemas and principal types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel


# ── Pydantic request/response models ─────────────────────────────────────────

class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str
    username: str | None = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ── Scope constants ───────────────────────────────────────────────────────────

class Scopes:
    """Well-known platform scope strings."""

    FLOW_READ       = "flow.read"
    FLOW_EXECUTE    = "flow.execute"
    MEMORY_READ     = "memory.read"
    MEMORY_WRITE    = "memory.write"
    AGENT_RUN       = "agent.run"
    WEBHOOK_MANAGE  = "webhook.manage"
    PLATFORM_ADMIN  = "platform.admin"

    ALL: list[str] = [
        FLOW_READ,
        FLOW_EXECUTE,
        MEMORY_READ,
        MEMORY_WRITE,
        AGENT_RUN,
        WEBHOOK_MANAGE,
        PLATFORM_ADMIN,
    ]


# ── Principal dataclass ───────────────────────────────────────────────────────

@dataclass
class AuthPrincipal:
    """Resolved authentication identity.

    ``auth_type="jwt"``    — JWT Bearer token; ``has_scope`` always returns True.
    ``auth_type="api_key"`` — Platform API key; scope-restricted.
    """

    user_id: str
    auth_type: str          # "jwt" | "api_key"
    scopes: list[str] = field(default_factory=list)
    key_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def has_scope(self, scope: str) -> bool:
        """Return True if this principal holds *scope*."""
        if self.auth_type == "jwt":
            return True   # JWT users carry full trust
        return scope in self.scopes or Scopes.PLATFORM_ADMIN in self.scopes
