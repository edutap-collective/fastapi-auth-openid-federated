"""Exception hierarchy for the federation layer.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations


class FederationError(Exception):
    """Base class for all federation-layer failures."""


class EntityStatementError(FederationError):
    """An entity statement is malformed, mistyped, or fails structural checks."""


class SignatureError(FederationError):
    """A JWS signature could not be verified (bad signature or no matching key)."""


class TrustChainError(FederationError):
    """A trust chain could not be resolved or validated up to a configured anchor."""


class MetadataPolicyError(FederationError):
    """A metadata policy is invalid, conflicts on merge, or fails on application."""


class FetchError(FederationError):
    """Fetching an entity configuration or subordinate statement failed."""
