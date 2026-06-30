"""Outbound HTTP transport for schema-driven tools (M4.8a).

Centralizes egress for the metadata-driven adapter engine (:mod:`atlas.adapter_engine`). Every
outbound call passes a host **allowlist** check before any network I/O (SSRF defense), and the
transport is injectable so the deterministic eval gate and unit tests stay hermetic — the
:class:`FakeTransport` never touches the network.

This is the "proxy-bound outbound routing" step of the lifecycle in its v1 form: an inline egress
allowlist. A real forward proxy (central TLS + credential injection) is a later slice; the allowlist
contract here is what that proxy would enforce, so swapping it in later is additive.
"""

from __future__ import annotations

import abc
from typing import Any
from urllib.parse import urlparse

import httpx

# No hidden retries anywhere: a retry after the provider has accepted a side effect can duplicate it
# within a single guarded execution (the same reasoning the existing senders document).
DEFAULT_EGRESS_TIMEOUT_SECONDS = 30.0


class EgressNotAllowed(RuntimeError):
    """Raised when an outbound request targets a host not on the egress allowlist (SSRF defense)."""


def host_of(url: str) -> str:
    """Return the lowercased hostname of ``url`` (fail-closed: a url with no host is rejected)."""
    host = urlparse(url).hostname
    if not host:
        raise EgressNotAllowed("outbound url has no host")
    return host.lower()


def assert_host_allowed(url: str, allowlist: frozenset[str]) -> None:
    """Reject ``url`` unless its host is on ``allowlist`` (exact, lowercased match)."""
    host = host_of(url)
    if host not in allowlist:
        raise EgressNotAllowed(f"host not on egress allowlist: {host}")


class Transport(abc.ABC):
    """Provider-agnostic outbound JSON transport contract."""

    @abc.abstractmethod
    def post_json(self, url: str, *, json: dict[str, Any], access_token: str) -> dict[str, Any]:
        """POST ``json`` to ``url`` with a bearer token; return the decoded JSON object."""
        raise NotImplementedError


class HttpxTransport(Transport):
    """Sync httpx POST — no hidden retries. Enforces the egress allowlist before any network call."""

    def __init__(
        self, allowlist: frozenset[str], *, timeout: float = DEFAULT_EGRESS_TIMEOUT_SECONDS
    ) -> None:
        self._allowlist = allowlist
        self._timeout = timeout

    def post_json(self, url: str, *, json: dict[str, Any], access_token: str) -> dict[str, Any]:
        assert_host_allowed(url, self._allowlist)
        response = httpx.post(
            url,
            json=json,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=self._timeout,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError("provider response was not a JSON object")
        return data


class FakeTransport(Transport):
    """Records outbound calls; never touches the network. Still enforces the allowlist (parity).

    ``response`` is the canned provider JSON returned to the caller; ``fail=True`` simulates an
    egress failure so degrade/idempotency paths stay testable offline.
    """

    def __init__(
        self,
        allowlist: frozenset[str] | None = None,
        *,
        response: dict[str, Any] | None = None,
        fail: bool = False,
    ) -> None:
        self._allowlist = allowlist
        self.calls: list[tuple[str, dict[str, Any], str]] = []
        self._response = response if response is not None else {"ok": True}
        self.fail = fail

    def post_json(self, url: str, *, json: dict[str, Any], access_token: str) -> dict[str, Any]:
        if self._allowlist is not None:
            assert_host_allowed(url, self._allowlist)
        if self.fail:
            raise RuntimeError("simulated egress failure")
        self.calls.append((url, json, access_token))
        return dict(self._response)
