"""Tests for the optional Redis/Postgres session stores (fakeredis / aiosqlite)."""

import fakeredis.aioredis
import pytest

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.postgres_store import PostgresStore
from fastapi_auth.openid.session.redis_store import RedisStore


def _identity() -> FederatedIdentity:
    return FederatedIdentity(sub="u1", mail=["u@lmu.de"])


@pytest.mark.asyncio
async def test_redis_store_round_trip():
    store = RedisStore(fakeredis.aioredis.FakeRedis())
    await store.save_session("sid", _identity(), ttl=300)
    loaded = await store.load_session("sid")
    assert loaded is not None
    assert loaded.sub == "u1"
    await store.delete_session("sid")
    assert await store.load_session("sid") is None
    await store.aclose()


@pytest.mark.asyncio
async def test_postgres_store_round_trip():
    from sqlalchemy.ext.asyncio import create_async_engine

    store = PostgresStore(create_async_engine("sqlite+aiosqlite:///:memory:"))
    await store.create_all()
    await store.save_session("sid", _identity(), ttl=300)
    loaded = await store.load_session("sid")
    assert loaded is not None
    assert loaded.mail == ["u@lmu.de"]
    await store.delete_session("sid")
    assert await store.load_session("sid") is None
    await store.aclose()


@pytest.mark.asyncio
async def test_postgres_store_expired_returns_none():
    from sqlalchemy.ext.asyncio import create_async_engine

    store = PostgresStore(create_async_engine("sqlite+aiosqlite:///:memory:"))
    await store.create_all()
    await store.save_session("sid", _identity(), ttl=-1)  # already expired
    assert await store.load_session("sid") is None
    await store.aclose()
