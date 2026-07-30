"""In-memory Store + Store protocol (ttl-based, injectable clock, lazy expiry).

Unlike the SAML package, this Store carries only the session methods: the OIDC
in-flight authorization state lives in the separate LoginStateStore (Plan 3).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

from fastapi_auth.openid.identity.model import FederatedIdentity


class Store(Protocol):
    """Session storage backend."""

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        ...

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        ...

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        ...

    async def aclose(self) -> None:
        """Release any resources held by the store (connections, pools, ...)."""
        ...


class MemoryStore:
    """Non-persistent Store (single process) with lazy TTL expiry."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        """Initialize an empty store using the given clock for TTL expiry."""
        self._clock = clock
        self._sessions: dict[str, tuple[FederatedIdentity, float]] = {}

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        self._sessions[sid] = (identity, self._clock() + ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        item = self._sessions.get(sid)
        if item is None:
            return None
        identity, expires_at = item
        if self._clock() > expires_at:
            self._sessions.pop(sid, None)
            return None
        return identity

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        self._sessions.pop(sid, None)

    async def aclose(self) -> None:
        """No-op: MemoryStore holds no external resources to release."""
