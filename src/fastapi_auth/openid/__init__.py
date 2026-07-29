"""Federated OpenID Connect Relying Party for FastAPI.

Public entry point of the ``fastapi_auth.openid`` package.
Import via ``from fastapi_auth import openid``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

from fastapi_auth.openid.identity.identifier import select_identifier
from fastapi_auth.openid.identity.mapper import map_claims
from fastapi_auth.openid.identity.model import FederatedIdentity

__all__ = [
    "FederatedIdentity",
    "__version__",
    "map_claims",
    "select_identifier",
]

__version__ = "0.1.0.dev0"
