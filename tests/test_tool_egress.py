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
from pydantic import ValidationError

from atlas.config import Settings
from atlas.tool_egress import (
    EgressNotAllowed,
    EgressPolicy,
    EgressRoute,
    HttpxTransport,
    ProxyTransport,
    assert_host_allowed,
    make_adapter_transport,
    resolve_safe_ip,
)

_HOST = "slack.com"
_PATH = "/api/chat.postMessage"
_URL = f"https://{_HOST}{_PATH}"
_POLICY = EgressPolicy(
    allowed_hosts=frozenset({_HOST}), routes=frozenset({EgressRoute("POST", _HOST, 443, _PATH)})
)


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


def test_assert_host_allowed_rejects_http() -> None:
    with pytest.raises(EgressNotAllowed, match="scheme not allowed"):
        assert_host_allowed(f"http://{_HOST}{_PATH}", frozenset({_HOST}))


def test_assert_host_allowed_rejects_userinfo() -> None:
    with pytest.raises(EgressNotAllowed, match="userinfo"):
        assert_host_allowed(f"https://user:pass@{_HOST}{_PATH}", frozenset({_HOST}))


# --- IP resolution / private + metadata block (fail-closed) ----------------


@pytest.mark.parametrize(
    "ip",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "169.254.169.254",
        "100.64.0.1",
        "100.127.255.254",
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
    assert headers["Host"] == _HOST  # original host preserved for routing (default port omitted)
    assert extensions["sni_hostname"] == _HOST  # TLS verifies against the real hostname


def test_prepare_pinned_host_header_includes_nonstandard_port(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    url = f"https://{_HOST}:8443{_PATH}"
    policy = EgressPolicy(
        allowed_hosts=frozenset({_HOST}),
        routes=frozenset({EgressRoute("POST", _HOST, 8443, _PATH)}),
    )
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning("93.184.216.34"))
    _, headers, _ = HttpxTransport(policy).prepare_pinned(url)
    assert headers["Host"] == f"{_HOST}:8443"


def test_sni_hostname_used_as_tls_server_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    import httpcore._backends.sync as sync_be

    for var in (
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
    ):
        monkeypatch.delenv(var, raising=False)

    captured: dict[str, str | None] = {}

    class _FakeStream:
        def start_tls(
            self,
            *,
            ssl_context: Any,
            server_hostname: str | None = None,
            timeout: float | None = None,
        ) -> Any:
            captured["server_hostname"] = server_hostname
            raise RuntimeError("stop after capture")

    def _fake_connect_tcp(
        self: Any,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Any = None,
    ) -> _FakeStream:
        return _FakeStream()

    monkeypatch.setattr(sync_be.SyncBackend, "connect_tcp", _fake_connect_tcp)
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning("93.184.216.34"))
    with pytest.raises(RuntimeError, match="stop after capture"):
        HttpxTransport(_POLICY).post_json(_URL, json={}, access_token="tok")
    assert captured["server_hostname"] == _HOST


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


def test_client_disables_trust_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("HTTP_PROXY", "http://evil:8080")
    captured: dict[str, Any] = {}

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def post(self, *args: Any, **kwargs: Any) -> Any:
            class _Resp:
                is_redirect = False

                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict[str, Any]:
                    return {"ok": True}

            return _Resp()

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setattr(socket, "getaddrinfo", _getaddrinfo_returning("93.184.216.34"))
    HttpxTransport(_POLICY).post_json(_URL, json={}, access_token="tok")
    assert captured.get("trust_env") is False


# --- proxy mode (M4.8b) ----------------------------------------------------


def test_make_adapter_transport_blank_proxy_returns_httpx_transport() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None)
    transport = make_adapter_transport(settings, _POLICY)
    assert isinstance(transport, HttpxTransport)
    assert not isinstance(transport, ProxyTransport)


def test_make_adapter_transport_proxy_url_returns_proxy_transport() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_ADAPTER_EGRESS_PROXY_URL="http://proxy.corp:8080",
    )
    transport = make_adapter_transport(settings, _POLICY)
    assert isinstance(transport, ProxyTransport)


def test_proxy_transport_passes_proxy_kwarg_and_disables_trust_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def post(self, *args: Any, **kwargs: Any) -> Any:
            captured["post_headers"] = kwargs.get("headers")
            captured["follow_redirects"] = kwargs.get("follow_redirects")

            class _Resp:
                is_redirect = False

                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict[str, Any]:
                    return {"ok": True}

            return _Resp()

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    monkeypatch.setenv("HTTP_PROXY", "http://evil:8080")
    transport = ProxyTransport(_POLICY, proxy_url="http://proxy.corp:8080")
    transport.post_json(_URL, json={"text": "hi"}, access_token="tok")
    proxy = captured.get("proxy")
    assert isinstance(proxy, httpx.Proxy)
    assert str(proxy.url) == "http://proxy.corp:8080"
    assert proxy.auth is None
    assert captured.get("trust_env") is False
    assert captured.get("post_headers") == {"Authorization": "Bearer tok"}
    assert captured.get("follow_redirects") is False


def test_proxy_transport_passes_proxy_auth_when_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            captured.update(kwargs)

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def post(self, *args: Any, **kwargs: Any) -> Any:
            class _Resp:
                is_redirect = False

                def raise_for_status(self) -> None:
                    pass

                def json(self) -> dict[str, Any]:
                    return {"ok": True}

            return _Resp()

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    transport = ProxyTransport(
        _POLICY,
        proxy_url="http://proxy.corp:8080",
        proxy_auth=("proxy-user", "proxy-pass"),
    )
    transport.post_json(_URL, json={}, access_token="tok")
    proxy = captured.get("proxy")
    assert isinstance(proxy, httpx.Proxy)
    assert str(proxy.url) == "http://proxy.corp:8080"
    assert proxy.auth == ("proxy-user", "proxy-pass")


def test_proxy_transport_rejects_off_allowlist_before_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            nonlocal called
            called = True

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("should not post")

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    transport = ProxyTransport(_POLICY, proxy_url="http://proxy.corp:8080")
    with pytest.raises(EgressNotAllowed):
        transport.post_json(f"https://evil.example.com{_PATH}", json={}, access_token="tok")
    assert not called


def test_proxy_transport_rejects_wrong_route_before_client(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            nonlocal called
            called = True

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def post(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("should not post")

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    transport = ProxyTransport(_POLICY, proxy_url="http://proxy.corp:8080")
    with pytest.raises(EgressNotAllowed):
        transport.post_json(f"https://{_HOST}/api/admin.delete", json={}, access_token="tok")
    assert not called


def test_proxy_transport_redirect_not_followed(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        is_redirect = True
        status_code = 302

    class _FakeClient:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            pass

        def __enter__(self) -> _FakeClient:
            return self

        def __exit__(self, *args: Any) -> None:
            pass

        def post(self, *args: Any, **kwargs: Any) -> _Resp:
            return _Resp()

    monkeypatch.setattr(httpx, "Client", _FakeClient)
    transport = ProxyTransport(_POLICY, proxy_url="http://proxy.corp:8080")
    with pytest.raises(EgressNotAllowed):
        transport.post_json(_URL, json={}, access_token="tok")


def test_proxy_url_with_userinfo_rejected_at_settings() -> None:
    with pytest.raises(ValidationError, match="userinfo"):
        Settings(
            ANTHROPIC_API_KEY=None,
            ATLAS_ADAPTER_EGRESS_PROXY_URL="http://user:pass@proxy.corp:8080",
        )


def test_proxy_url_with_invalid_scheme_rejected_at_settings() -> None:
    with pytest.raises(ValidationError, match="http or https"):
        Settings(
            ANTHROPIC_API_KEY=None,
            ATLAS_ADAPTER_EGRESS_PROXY_URL="socks5://proxy.corp:1080",
        )


def test_proxy_url_with_userinfo_rejected_at_transport_init() -> None:
    with pytest.raises(EgressNotAllowed, match="userinfo"):
        ProxyTransport(_POLICY, proxy_url="http://user:pass@proxy.corp:8080")


def test_proxy_url_with_invalid_scheme_rejected_at_transport_init() -> None:
    with pytest.raises(EgressNotAllowed, match="proxy url scheme not allowed"):
        ProxyTransport(_POLICY, proxy_url="socks5://proxy.corp:1080")
