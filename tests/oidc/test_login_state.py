"""Tests for the transient login-state store."""

from fastapi_auth.openid.login_state import LoginState, LoginStateStore

NOW = 1_700_000_000


def _state(value: str = "s1") -> LoginState:
    return LoginState(
        state=value,
        nonce="n1",
        code_verifier="v1",
        op_entity_id="https://op.example",
        next_url="/app",
        op_metadata={"issuer": "https://op.example"},
        created=NOW,
    )


def test_put_then_pop_returns_state_once():
    store = LoginStateStore(ttl=300)
    store.put(_state("abc"))
    got = store.pop("abc", now=NOW + 10)
    assert got is not None
    assert got.nonce == "n1"
    # one-time use: second pop is None
    assert store.pop("abc", now=NOW + 10) is None


def test_pop_unknown_returns_none():
    assert LoginStateStore(ttl=300).pop("nope", now=NOW) is None


def test_expired_state_is_evicted():
    store = LoginStateStore(ttl=300)
    store.put(_state("old"))
    assert store.pop("old", now=NOW + 1000) is None
