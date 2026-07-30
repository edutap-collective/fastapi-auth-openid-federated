"""Transient login-state store: correlates an OIDC callback with its request.

Holds the short-lived ``state``/``nonce``/``code_verifier`` (and the resolved
OP metadata) between ``/login`` and ``/callback``. State is single-use and
expires after ``ttl`` seconds. This is NOT the user session (that is Plan 4);
it is the OIDC equivalent of the SAML in-flight AuthnRequest cache.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import time
from dataclasses import dataclass


@dataclass(frozen=True)
class LoginState:
    """Correlated state for one in-flight authorization-code login."""

    state: str
    nonce: str
    code_verifier: str
    op_entity_id: str
    next_url: str
    op_metadata: dict[str, object]
    created: int


class LoginStateStore:
    """In-memory, single-use, TTL-bounded store keyed by ``state``."""

    def __init__(self, ttl: int = 300) -> None:
        """Create a store whose entries expire ``ttl`` seconds after creation."""
        self._ttl = ttl
        self._entries: dict[str, LoginState] = {}

    def put(self, state: LoginState) -> None:
        """Store a login state under its ``state`` value."""
        self._entries[state.state] = state

    def pop(self, state_value: str, *, now: int | None = None) -> LoginState | None:
        """Remove and return the state; None if unknown, expired, or already used."""
        moment = int(time.time()) if now is None else now
        entry = self._entries.pop(state_value, None)
        if entry is None:
            return None
        if entry.created + self._ttl <= moment:
            return None
        return entry
