"""Configuration for the OpenID Connect relying party (pydantic-settings).

Trust is established via OpenID Federation (Plan 2): ``trust_anchors`` are the
out-of-band-configured anchors a resolved chain must terminate at, and
``fed_jwks`` are this RP's federation keys (private material) used to sign the
entity configuration, request objects and client assertions.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_WELL_KNOWN_PATH = "/.well-known/openid-federation"


class OidcSettings(BaseSettings):
    """Relying-party settings, populated from environment (prefix ``OIDC_``)."""

    model_config = SettingsConfigDict(env_prefix="OIDC_", env_file=".env", extra="ignore")

    # --- entity / endpoints ---
    entity_id: str
    base_url: str
    mount_path: str = "/openid"
    redirect_path: str = "/openid/callback"

    # --- federation keys / trust ---
    fed_jwks: dict[str, object]
    authority_hints: list[str] = Field(default_factory=list)
    trust_anchors: dict[str, dict[str, object]] = Field(default_factory=dict)
    rp_metadata: dict[str, object] = Field(default_factory=dict)

    # --- OIDC request ---
    scopes: list[str] = Field(default_factory=lambda: ["openid", "profile", "email"])
    id_token_signing_alg_values: list[str] = Field(default_factory=lambda: ["RS256", "ES256"])
    fetch_userinfo: bool = False

    # --- lifetimes / skew (seconds) ---
    request_object_lifetime: int = 120
    client_assertion_lifetime: int = 60
    login_state_ttl: int = 300
    clock_skew: int = 60

    # --- security ---
    allowed_redirect_hosts: list[str] = Field(default_factory=list)

    # --- session ---
    session_cookie_name: str = "fa_openid_session"
    session_secret: str | None = None
    session_ttl: int = 28800
    cookie_secure: bool = True

    # --- session backend / store selection ---
    backend: Literal["cookie", "jwt"] = "cookie"
    store: Literal["memory", "redis", "postgres"] = "memory"
    redis_url: str = "redis://localhost:6379/0"
    db_url: str = "sqlite+aiosqlite:///:memory:"

    # --- JWT backend (opt-in; joserfc) ---
    jwt_alg: str = "HS256"
    jwt_ttl: int = 3600
    jwt_secret: str | None = None
    # Asymmetric jwt_alg (RS256, ES256, EdDSA, ...): sign with the first private
    # key in jwt_jwks, verify with its public half — other services can verify
    # without being able to mint tokens.
    jwt_jwks: dict[str, object] | None = None
    # Data minimisation: when set, only these FederatedIdentity field names are
    # carried in the token's "attrs" claim.
    jwt_attributes: list[str] | None = None

    @model_validator(mode="after")
    def _check_redirect_under_mount(self) -> OidcSettings:
        if not self.redirect_path.startswith(self.mount_path):
            raise ValueError(
                f"redirect_path {self.redirect_path!r} must start with "
                f"mount_path {self.mount_path!r}"
            )
        return self

    @property
    def _root(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def callback_url(self) -> str:
        """Absolute redirect_uri registered with / sent to the OP."""
        return self._root + self.redirect_path

    @property
    def well_known_path(self) -> str:
        """Path of this RP's entity configuration."""
        return _WELL_KNOWN_PATH

    def absolute_url(self, path: str) -> str:
        """Absolute URL for a router path relative to ``mount_path``."""
        suffix = path if path.startswith("/") else f"/{path}"
        return f"{self._root}{self.mount_path}{suffix}"

    def jwt_is_symmetric(self) -> bool:
        """Return whether ``jwt_alg`` is a symmetric (HMAC) algorithm."""
        return self.jwt_alg.startswith("HS")

    @property
    def jwt_signing_secret(self) -> str:
        """Secret used to sign symmetric app JWTs (defaults to the session secret)."""
        return self.jwt_secret or self.session_secret or ""

    @model_validator(mode="after")
    def _check_jwt_alg_not_none(self) -> OidcSettings:
        """Reject unsigned JWT algorithms.

        The jwt_alg must not be 'none' or empty, as unsigned tokens are
        forgeable and pose a critical security risk.
        """
        if self.jwt_alg.strip().lower() in {"none", ""}:
            raise ValueError("jwt_alg must not be 'none' (unsigned tokens are forbidden)")
        return self

    @model_validator(mode="after")
    def _check_jwt_secret_strength(self) -> OidcSettings:
        """Ensure the JWT backend has strong-enough key material.

        Symmetric algorithms (HS*) need a shared secret of at least 32 bytes;
        asymmetric algorithms need a ``jwt_jwks`` with a private key. Only
        enforced when ``backend == "jwt"``.
        """
        if self.backend != "jwt":
            return self
        if self.jwt_is_symmetric():
            if len(self.jwt_signing_secret.encode()) < 32:
                raise ValueError(
                    "JWT backend requires jwt_secret/session_secret of at least 32 bytes"
                )
        elif self.jwt_jwks is None:
            raise ValueError("JWT backend with an asymmetric jwt_alg requires jwt_jwks")
        return self
