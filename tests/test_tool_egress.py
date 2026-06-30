"""SSRF-hardening tests for the schema-tool egress transport (M4.8b).

Covers the OWASP-aligned guards: single-parse/single-authority URL handling, https-only + no userinfo,
host + per-tool route allowlisting, resolve-then-validate-IP against private/metadata ranges, IP-pinned
connect with preserved Host/SNI, and redirects never followed.
"""

from __future__ import annotations

import socket
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from atlas.tool_egress import (
    EgressNotAllowed,
    EgressPolicy,
    EgressRoute,
    HttpxTransport,
    resolve_safe_ip,
)

_HOST = "slack.com"
_PATH = "/api/chat.postMessage"
_URL = f"https://{_HOST}{_PATH}"
_POLICY = EgressPolicy(frozenset({_HOST}), frozenset({EgressRoute("POST", _HOST, 443, _PATH)}))


def _getaddrinfo_returning(ip: str) -> Callable[..., list[tuple[Any, ...]]]:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    def _fake(host: str, port: int | None, *args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        return [(family, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port or 443))]

    return _fake


# --- scheme / userinfo / host / route allowlisting -------------------------


def test_https_required() -> None:
    with pytest.raises(EgressNotAllowed):
        _POLICY.assert_allowed(httpx.URL(f"http://{_HOST}{_PATH}"))


def test_userinfo_rejected() -> None:
    with pytest.raises(EgressNotAllowed):
        _POLICY.assert_allowed(httpx.URL(f"https://user:pass@{_HOST}{_PATH}"))


def test_host_not_allowlisted_rejected() -> None:
    with pytest.raises(EgressNotAllowed):
        _POLICY.assert_allowed(httpx.URL(f"https://evil.example.com{_PATH}"))


def test_route_path_mismatch_rejected() -> None:
    # Right host, wrong path => a valid domain cannot become a catch-all API tunnel.
    with pytest.raises(EgressNotAllowed):
        _POLICY.assert_allowed(httpx.URL(f"https://{_HOST}/api/admin.delete"))


def test_route_port_mismatch_rejected() -> None:
    # Right host + path, non-allowlisted port => rejected (route pins port too).
    with pytest.raises(EgressNotAllowed):
        _POLICY.assert_allowed(httpx.URL(f"https://{_HOST}:8443{_PATH}"))


def test_allowed_route_passes() -> None:
    _POLICY.assert_allowed(httpx.URL(_URL))  # must not raise (default 443)


# --- IP resolution / private + metadata block (fail-closed) ----------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "::1",
        "::ffff:10.0.0.1",
        "0.0.0.0",
    ],
)
def test_blocked_ip_ranges_rejected(monkeypatch: pytest.MonkeyPatch, ip: str) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning(ip))
    with pytest.raises(EgressNotAllowed):
        resolve_safe_ip(_HOST, 443)


def test_public_ip_allowed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning("93.184.216.34"))
    assert resolve_safe_ip(_HOST, 443) == "93.184.216.34"


def test_unresolvable_host_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    def _boom(*args: Any, **kwargs: Any) -> list[tuple[Any, ...]]:
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", _boom)
    with pytest.raises(EgressNotAllowed):
        resolve_safe_ip(_HOST, 443)


# --- pinned connect params (parse once, connect under same interpretation) --


def test_prepare_pinned_pins_ip_and_preserves_host_and_sni(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning("93.184.216.34"))
    pinned, headers, extensions = HttpxTransport(_POLICY).prepare_pinned(_URL)
    assert pinned.host == "93.184.216.34"  # connect to the validated IP
    assert headers["Host"] == _HOST  # original host preserved for routing
    assert extensions["sni_hostname"] == _HOST  # TLS verifies against the real hostname


# --- redirects never followed ----------------------------------------------


def test_redirect_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning("93.184.216.34"))

    class _Resp:
        is_redirect = True
        status_code = 302

    def _fake_post(self: httpx.Client, *args: Any, **kwargs: Any) -> _Resp:
        assert kwargs.get("follow_redirects") is False
        return _Resp()

    monkeypatch.setattr(httpx.Client, "post", _fake_post)
    with pytest.raises(EgressNotAllowed):
        HttpxTransport(_POLICY).post_json(_URL, json={}, access_token="tok")
