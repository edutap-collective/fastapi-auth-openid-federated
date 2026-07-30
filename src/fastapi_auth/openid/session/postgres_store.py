"""Postgres-backed session Store via SQLModel async (test: SQLite/aiosqlite).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import Field, SQLModel

from fastapi_auth.openid.identity.model import FederatedIdentity


class OpenidSession(SQLModel, table=True):
    """SQLModel table for a stored session (identity JSON + expiry)."""

    sid: str = Field(primary_key=True)
    data: str
    expires_at: float


class PostgresStore:
    """Session Store backed by an async SQLAlchemy engine (Postgres/SQLite)."""

    def __init__(self, engine: Any) -> None:
        """Wrap an existing async SQLAlchemy engine."""
        self._engine = engine

    @classmethod
    def from_url(cls, url: str) -> PostgresStore:
        """Build a PostgresStore from a database URL, lazily importing SQLAlchemy."""
        try:
            from sqlalchemy.ext.asyncio import create_async_engine
        except ModuleNotFoundError as err:  # pragma: no cover - import guard
            msg = (
                "PostgresStore requires the 'postgres' extra: "
                "pip install 'fastapi-auth-openid-federated[postgres]'"
            )
            raise RuntimeError(msg) from err
        return cls(create_async_engine(url))

    async def create_all(self) -> None:
        """Create all tables (used directly in tests; migrations own this in prod)."""
        async with self._engine.begin() as conn:
            await conn.run_sync(SQLModel.metadata.create_all)

    async def save_session(self, sid: str, identity: FederatedIdentity, ttl: int) -> None:
        """Save a session with its associated identity, expiring after ``ttl`` seconds."""
        async with AsyncSession(self._engine) as s:
            await s.merge(
                OpenidSession(
                    sid=sid,
                    data=identity.model_dump_json(),
                    expires_at=time.time() + ttl,
                )
            )
            await s.commit()

    async def load_session(self, sid: str) -> FederatedIdentity | None:
        """Load a session identity by session ID, or None if not found or expired."""
        async with AsyncSession(self._engine) as s:
            row = await s.get(OpenidSession, sid)
            if row is None:
                return None
            if row.expires_at < time.time():
                await s.delete(row)
                await s.commit()
                return None
            return FederatedIdentity.model_validate_json(row.data)

    async def delete_session(self, sid: str) -> None:
        """Delete a session by session ID (no-op if not found)."""
        async with AsyncSession(self._engine) as s:
            row = await s.get(OpenidSession, sid)
            if row is not None:
                await s.delete(row)
                await s.commit()

    async def aclose(self) -> None:
        """Dispose the wrapped engine, releasing its connection pool."""
        await self._engine.dispose()
