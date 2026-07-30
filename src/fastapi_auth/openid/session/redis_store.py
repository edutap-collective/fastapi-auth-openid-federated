"""Redis-backed session Store (redis.asyncio, native key TTL).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Any

from fastapi_auth.openid.identity.model import FederatedIdentity


class RedisStore:
    """Session Store backed by Redis; sessions are keys with native TTL."""

    def __init__(self, client: Any, *, session_prefix: str = "fa:oidc:sess:") -> None:
        """Wrap an existing ``redis.asyncio.Redis``-compatible client."""
        self._r = client
        self._sp = session_prefix

    @classmethod
    def from_url(cls, url: str) -> RedisStore:
        """Build a RedisStore from a redis:// URL, lazily importing redis.asyncio."""
        try:
            import redis.asyncio as redis_async
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = (
                "RedisStore requires the 'redis' extra: "
                "pip install 'fastapi-auth-openid-federated[redis]'"
            )
            raise RuntimeError(msg) from err
        return cls(redis_async.from_url(url))

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        await self._r.set(f"{self._sp}{sid}", identity.model_dump_json(), ex=ttl)

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        raw = await self._r.get(f"{self._sp}{sid}")
        if raw is None:
            return None
        return FederatedIdentity.model_validate_json(raw)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        await self._r.delete(f"{self._sp}{sid}")

    async def aclose(self) -> None:
        """Close the wrapped Redis client, releasing its connection pool."""
        await self._r.aclose()
