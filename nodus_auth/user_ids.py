"""UUID user ID parsing utilities."""
from __future__ import annotations

import uuid
from typing import Iterable


def parse_user_id(value: str | uuid.UUID | None) -> uuid.UUID | None:
    """Parse *value* into a UUID, returning None on failure."""
    if value is None or value == "":
        return None
    if isinstance(value, uuid.UUID):
        return value
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def require_user_id(value: str | uuid.UUID | None) -> uuid.UUID:
    """Parse *value* into a UUID. Raises ``ValueError`` if parsing fails."""
    parsed = parse_user_id(value)
    if parsed is None:
        raise ValueError("user_id is required")
    return parsed


def parse_user_ids(values: Iterable[str | uuid.UUID | None]) -> list[uuid.UUID]:
    """Parse an iterable of values, silently skipping unparseable entries."""
    parsed: list[uuid.UUID] = []
    for value in values:
        user_id = parse_user_id(value)
        if user_id is not None:
            parsed.append(user_id)
    return parsed
