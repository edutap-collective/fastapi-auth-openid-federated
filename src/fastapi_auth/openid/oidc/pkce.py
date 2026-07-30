"""PKCE code verifier and S256 challenge (RFC 7636).

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import base64
import hashlib
import secrets


def create_code_verifier() -> str:
    """Return a high-entropy code verifier (unreserved chars, 43-128 length)."""
    return secrets.token_urlsafe(64)


def code_challenge_s256(verifier: str) -> str:
    """Return BASE64URL(SHA256(verifier)) without padding (``S256`` method)."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
