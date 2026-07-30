"""Tests for the in-memory session store."""

import pytest

from fastapi_auth.openid.identity.model import FederatedIdentity
from fastapi_auth.openid.session.store import MemoryStore


def _identity() -> FederatedIdentity:
    return FederatedIdentity(sub="u1", mail=["u@lmu.de"])


@pytest.mark.asyncio
async def test_save_load_delete():
    clock = [1000.0]
    store = MemoryStore(clock=lambda: clock[0])
    await store.save_session("sid", _identity(), ttl=300)
    loaded = await store.load_session("sid")
    assert loaded is not None
    assert loaded.sub == "u1"
    await store.delete_session("sid")
    assert await store.load_session("sid") is None


@pytest.mark.asyncio
async def test_expired_session_is_evicted():
    clock = [1000.0]
    store = MemoryStore(clock=lambda: clock[0])
    await store.save_session("sid", _identity(), ttl=300)
    clock[0] = 2000.0
    assert await store.load_session("sid") is None


@pytest.mark.asyncio
async def test_load_unknown_returns_none():
    assert await MemoryStore().load_session("nope") is None


@pytest.mark.asyncio
async def test_aclose_is_noop():
    await MemoryStore().aclose()  # must not raise
