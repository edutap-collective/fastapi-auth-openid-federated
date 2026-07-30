"""Integration tests for the optional stores against live Redis/Postgres.

Skipped unless IT_REDIS_URL / IT_DB_URL are set (see `make test-integration`).
"""

import os

import pytest

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.postgres_store import PostgresStore
from fastapi_auth.openid.session.redis_store import RedisStore

pytestmark = pytest.mark.integration

_REDIS_URL = os.environ.get("IT_REDIS_URL")
_DB_URL = os.environ.get("IT_DB_URL")


def _identity() -> FederatedIdentity:
    return FederatedIdentity(sub="u1", mail=["u@lmu.de"])


@pytest.mark.skipif(_REDIS_URL is None, reason="IT_REDIS_URL not set")
@pytest.mark.asyncio
async def test_redis_store_live_round_trip():
    assert _REDIS_URL is not None
    store = RedisStore.from_url(_REDIS_URL)
    try:
        await store.save_session("it-sid", _identity(), ttl=60)
        loaded = await store.load_session("it-sid")
        assert loaded is not None
        assert loaded.sub == "u1"
        await store.delete_session("it-sid")
        assert await store.load_session("it-sid") is None
    finally:
        await store.aclose()


@pytest.mark.skipif(_DB_URL is None, reason="IT_DB_URL not set")
@pytest.mark.asyncio
async def test_postgres_store_live_round_trip():
    assert _DB_URL is not None
    store = PostgresStore.from_url(_DB_URL)
    try:
        await store.create_all()
        await store.save_session("it-sid", _identity(), ttl=60)
        loaded = await store.load_session("it-sid")
        assert loaded is not None
        assert loaded.mail == ["u@lmu.de"]
        await store.delete_session("it-sid")
    finally:
        await store.aclose()
