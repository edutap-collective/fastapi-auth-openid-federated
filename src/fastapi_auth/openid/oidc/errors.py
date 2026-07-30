"""Exception hierarchy for the OIDC relying-party layer.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations


class OidcError(Exception):
    """Base class for all OIDC relying-party failures."""


class AuthorizationError(OidcError):
    """The authorization request could not be built or the callback is malformed."""


class TokenExchangeError(OidcError):
    """The token endpoint returned an error or an unusable response."""


class IdTokenError(OidcError):
    """The ID token failed signature or claim validation."""


class LoginStateError(OidcError):
    """The login state is unknown, expired, or already used (possible CSRF)."""
