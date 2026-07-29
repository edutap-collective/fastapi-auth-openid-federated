"""Build and verify OpenID Federation entity statements.

An entity statement is a signed JWT with ``typ`` = ``entity-statement+jwt``
(Section 3). When ``iss == sub`` it is a self-issued Entity Configuration;
otherwise it is a Subordinate Statement issued by a superior about its
subordinate. The ``jwks`` claim always carries the *subject's* federation keys.

Verification here combines three checks that the spec keeps distinct:
signature (via ``jose.verify_signature``), structural typing (``typ`` +
required claims), and freshness (``iat``/``exp`` with clock skew). ``joserfc``
does none of the latter two automatically.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from collections.abc import Sequence

from joserfc.jwk import Key, KeySet

from fastapi_auth.openid.federation import jose
from fastapi_auth.openid.federation.errors import EntityStatementError

REQUIRED_CLAIMS: tuple[str, ...] = ("iss", "sub", "iat", "exp", "jwks")


def build_entity_configuration(
    *,
    entity_id: str,
    jwks: dict[str, object],
    authority_hints: Sequence[str] | None = None,
    metadata: dict[str, object] | None = None,
    lifetime: int = 3600,
    now: int | None = None,
) -> dict[str, object]:
    """Build the claims of a self-issued Entity Configuration (``iss == sub``)."""
    issued = jose.now_epoch() if now is None else now
    claims: dict[str, object] = {
        "iss": entity_id,
        "sub": entity_id,
        "iat": issued,
        "exp": issued + lifetime,
        "jwks": jwks,
    }
    if authority_hints is not None:
        claims["authority_hints"] = list(authority_hints)
    if metadata is not None:
        claims["metadata"] = metadata
    return claims


def build_subordinate_statement(
    *,
    issuer: str,
    subject: str,
    jwks: dict[str, object],
    metadata: dict[str, object] | None = None,
    metadata_policy: dict[str, object] | None = None,
    constraints: dict[str, object] | None = None,
    lifetime: int = 3600,
    now: int | None = None,
) -> dict[str, object]:
    """Build the claims of a Subordinate Statement (``iss != sub``, no hints)."""
    issued = jose.now_epoch() if now is None else now
    claims: dict[str, object] = {
        "iss": issuer,
        "sub": subject,
        "iat": issued,
        "exp": issued + lifetime,
        "jwks": jwks,
    }
    if metadata is not None:
        claims["metadata"] = metadata
    if metadata_policy is not None:
        claims["metadata_policy"] = metadata_policy
    if constraints is not None:
        claims["constraints"] = constraints
    return claims


def is_entity_configuration(claims: dict[str, object]) -> bool:
    """Check if the statement is self-issued (Entity Configuration)."""
    return claims.get("iss") == claims.get("sub")


def check_structure(claims: dict[str, object]) -> None:
    """Ensure all REQUIRED entity-statement claims are present."""
    for name in REQUIRED_CLAIMS:
        if name not in claims:
            raise EntityStatementError(f"entity statement missing required claim: {name!r}")


def check_time(claims: dict[str, object], *, leeway: int = 0, now: int | None = None) -> None:
    """Validate ``iat`` (not in the future) and ``exp`` (not past), with skew."""
    moment = jose.now_epoch() if now is None else now
    iat = claims.get("iat")
    exp = claims.get("exp")
    if not isinstance(iat, int) or not isinstance(exp, int):
        raise EntityStatementError("entity statement has non-integer iat/exp")
    if iat > moment + leeway:
        raise EntityStatementError("entity statement iat is in the future")
    if exp < moment - leeway:
        raise EntityStatementError("entity statement is expired")


def verify_statement(
    token: str,
    keyset: KeySet | Key,
    *,
    algorithms: Sequence[str] = jose.DEFAULT_SIGNING_ALGORITHMS,
    leeway: int = 0,
    now: int | None = None,
) -> dict[str, object]:
    """Verify signature, ``typ``, required claims and freshness of a statement."""
    header = jose.peek_header(token)
    if header.get("typ") != jose.ENTITY_STATEMENT_TYP:
        raise EntityStatementError(f"entity statement has wrong typ: {header.get('typ')!r}")
    claims = jose.verify_signature(token, keyset, algorithms=algorithms)
    check_structure(claims)
    check_time(claims, leeway=leeway, now=now)
    return claims
