"""Configuration for the OpenID Connect relying party (pydantic-settings).

Trust is established via OpenID Federation (Plan 2): ``trust_anchors`` are the
out-of-band-configured anchors a resolved chain must terminate at, and
``fed_jwks`` are this RP's federation keys (private material) used to sign the
entity configuration, request objects and client assertions.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

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
