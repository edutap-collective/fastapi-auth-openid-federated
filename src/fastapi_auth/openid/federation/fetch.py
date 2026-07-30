"""Async HTTP fetch layer for federation endpoints.

Retrieves Entity Configurations from ``/.well-known/openid-federation``
(Section 9) and Subordinate Statements from a superior's federation fetch
endpoint with a single ``sub`` query parameter (Section 8.1). Both responses
carry ``application/entity-statement+jwt``.

SPDX-License-Identifier: Apache-2.0 OR EUPL-1.2
"""

from __future__ import annotations

import httpx

from fastapi_auth.openid.federation.errors import FetchError

ENTITY_STATEMENT_CONTENT_TYPE = "application/entity-statement+jwt"
_WELL_KNOWN_SUFFIX = "/.well-known/openid-federation"


def well_known_url(entity_id: str) -> str:
    """Build the entity configuration URL by suffix-concatenation (Section 9)."""
    return entity_id.rstrip("/") + _WELL_KNOWN_SUFFIX


def _check_content_type(response: httpx.Response) -> None:
    content_type = response.headers.get("content-type", "")
    if not content_type.startswith(ENTITY_STATEMENT_CONTENT_TYPE):
        raise FetchError(
            f"unexpected content-type {content_type!r} "
            f"(want {ENTITY_STATEMENT_CONTENT_TYPE!r}) from {response.request.url}"
        )


async def fetch_entity_configuration(client: httpx.AsyncClient, entity_id: str) -> str:
    """GET the self-issued Entity Configuration for ``entity_id``."""
    url = well_known_url(entity_id)
    try:
        response = await client.get(url)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise FetchError(f"failed to fetch entity configuration from {url}: {exc}") from exc
    _check_content_type(response)
    return response.text


async def fetch_subordinate_statement(
    client: httpx.AsyncClient,
    fetch_endpoint: str,
    subject: str,
) -> str:
    """GET a Subordinate Statement about ``subject`` from a fetch endpoint."""
    try:
        response = await client.get(fetch_endpoint, params={"sub": subject})
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise FetchError(
            f"failed to fetch subordinate statement for {subject} from {fetch_endpoint}: {exc}"
        ) from exc
    _check_content_type(response)
    return response.text


async def list_subordinates(
    client: httpx.AsyncClient,
    list_endpoint: str,
    *,
    entity_type: str | None = None,
) -> list[str]:
    """List a superior's subordinate entity identifiers (Section 8.2).

    Optionally filtered to one ``entity_type`` (e.g. ``openid_provider``). The
    response is a JSON array of entity identifier strings.
    """
    params = {"entity_type": entity_type} if entity_type is not None else None
    try:
        response = await client.get(list_endpoint, params=params)
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise FetchError(f"failed to list subordinates from {list_endpoint}: {exc}") from exc
    data = response.json()
    if not isinstance(data, list) or not all(isinstance(item, str) for item in data):
        raise FetchError(f"list endpoint {list_endpoint} did not return a JSON array of strings")
    return data
