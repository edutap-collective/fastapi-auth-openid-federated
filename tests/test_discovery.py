"""Tests for the embedded WAYF renderer."""

from jinja2 import Environment, FileSystemLoader, select_autoescape

from fastapi_auth.openid.discovery import embedded
from fastapi_auth.openid.discovery.embedded import OpChoice


def _env() -> Environment:
    from pathlib import Path

    import fastapi_auth.openid.discovery as disco_pkg

    templates = Path(disco_pkg.__file__).parent / "templates"
    return Environment(loader=FileSystemLoader(str(templates)), autoescape=select_autoescape())


def test_render_lists_ops_with_login_links():
    ops = [
        OpChoice(entity_id="https://op1.example", display_name="OP One"),
        OpChoice(entity_id="https://op2.example", display_name="OP Two"),
    ]
    html = embedded.render_wayf(ops, "/openid/login", "/app", _env())
    assert "OP One" in html
    assert "OP Two" in html
    assert "op=https%3A%2F%2Fop1.example" in html
    assert "next=%2Fapp" in html


def test_render_escapes_untrusted_display_name():
    ops = [OpChoice(entity_id="https://evil.example", display_name="<script>alert(1)</script>")]
    html = embedded.render_wayf(ops, "/openid/login", "/app", _env())
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_empty_list_produces_page():
    html = embedded.render_wayf([], "/openid/login", "/", _env())
    assert "<html" in html.lower()
