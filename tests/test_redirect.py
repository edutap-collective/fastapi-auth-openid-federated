"""Tests for the open-redirect guard."""

from fastapi_auth.openid.redirect import is_safe_redirect


def test_local_paths_pass():
    assert is_safe_redirect("/app", []) == "/app"


def test_protocol_relative_rejected():
    assert is_safe_redirect("//evil.example", []) == "/"
    assert is_safe_redirect("/\\evil.example", []) == "/"


def test_control_chars_rejected():
    assert is_safe_redirect("/app\nSet-Cookie: x", []) == "/"


def test_absolute_url_only_if_allowlisted():
    assert is_safe_redirect("https://ok.example/x", ["ok.example"]) == "https://ok.example/x"
    assert is_safe_redirect("https://evil.example/x", ["ok.example"]) == "/"
