"""Tests for the async federation fetch layer."""

import httpx
import pytest
import respx

from fastapi_auth.openid.federation import fetch
from fastapi_auth.openid.federation.errors import FetchError


def test_well_known_url_strips_trailing_slash_and_suffixes_path():
    assert (
        fetch.well_known_url("https://op.example")
        == "https://op.example/.well-known/openid-federation"
    )
    assert (
        fetch.well_known_url("https://op.example/")
        == "https://op.example/.well-known/openid-federation"
    )
    # Path components are preserved as a suffix (spec Section 9).
    assert (
        fetch.well_known_url("https://host.example/tenant/a")
        == "https://host.example/tenant/a/.well-known/openid-federation"
    )


@pytest.mark.asyncio
async def test_fetch_entity_configuration_returns_body():
    url = fetch.well_known_url("https://op.example")
    with respx.mock:
        respx.get(url).respond(
            200,
            text="signed.jwt.here",
            headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE},
        )
        async with httpx.AsyncClient() as client:
            body = await fetch.fetch_entity_configuration(client, "https://op.example")
    assert body == "signed.jwt.here"


@pytest.mark.asyncio
async def test_fetch_subordinate_statement_passes_sub_param():
    with respx.mock:
        route = respx.get("https://ta.example/fetch").respond(
            200, text="sub.stmt.jwt", headers={"content-type": fetch.ENTITY_STATEMENT_CONTENT_TYPE}
        )
        async with httpx.AsyncClient() as client:
            body = await fetch.fetch_subordinate_statement(
                client, "https://ta.example/fetch", "https://op.example"
            )
    assert body == "sub.stmt.jwt"
    assert route.calls.last.request.url.params["sub"] == "https://op.example"


@pytest.mark.asyncio
async def test_fetch_raises_on_http_error():
    url = fetch.well_known_url("https://missing.example")
    with respx.mock:
        respx.get(url).respond(404)
        async with httpx.AsyncClient() as client:
            with pytest.raises(FetchError):
                await fetch.fetch_entity_configuration(client, "https://missing.example")


@pytest.mark.asyncio
async def test_fetch_raises_on_wrong_content_type():
    url = fetch.well_known_url("https://op.example")
    with respx.mock:
        respx.get(url).respond(200, text="<html>", headers={"content-type": "text/html"})
        async with httpx.AsyncClient() as client:
            with pytest.raises(FetchError, match="content-type"):
                await fetch.fetch_entity_configuration(client, "https://op.example")
