"""Outbound HTTP transport for schema-driven tools (M4.8a; SSRF-hardened M4.8b).

SSRF defense in depth (OWASP). The crux is **single-parse / single-authority**: a request is parsed
**once** into an :class:`httpx.URL`, and that one object is threaded through every stage — scheme/userinfo
validation, host + route allowlisting, DNS resolution, and the send — so there is never a
parser-differential gap (validate one string, fetch another). On top of a coarse host allowlist we
enforce a per-tool **(method, host, path) route** allowlist (a valid host cannot become a catch-all API
tunnel), resolve the host and reject any address in a private/loopback/link-local/reserved range
(blocking cloud-metadata ``169.254.169.254`` and internal ranges), then connect **pinned** to that
validated IP while preserving TLS via the ``Host`` header + ``sni_hostname`` extension. Redirects are
never followed (a redirect would fetch a URL that was never validated).

The transport is injectable so the deterministic eval gate and unit tests stay hermetic — the
:class:`FakeTransport` never touches the network. Proxy mode is intentionally **not** here yet (a
misconfigured proxy is itself an egress risk; it gets its own isolated, tested slice).
"""

from __future__ import annotations

import abc
import ipaddress
import socket
from typing import Any, NamedTuple

import httpx

# No hidden retries anywhere: a retry after the provider has accepted a side effect can duplicate it
# within a single guarded execution (the same reasoning the existing senders document).
DEFAULT_EGRESS_TIMEOUT_SECONDS = 30.0
# Schema tools are POST-only today; declared so the route allowlist can pin the method too.
ALLOWED_METHOD = "POST"
_DEFAULT_HTTPS_PORT = 443


class EgressNotAllowed(RuntimeError):
    """Raised when an outbound request is refused by an SSRF guard (scheme/userinfo/host/route/IP/redirect)."""


class EgressRoute(NamedTuple):
    """An exact ``(method, host, port, path)`` an outbound call must match. Hashable for set membership."""

    method: str
    host: str
    port: int
    path: str


class EgressPolicy:
    """The egress allowlist: a coarse host allowlist plus exact per-tool ``(method, host, path)`` routes.

    A request must satisfy **both** (host on the operator allowlist AND an exact route from a loaded
    schema). The route check is what stops a valid host from being tunneled to arbitrary paths.
    """

    def __init__(self, allowed_hosts: frozenset[str], routes: frozenset[EgressRoute]) -> None:
        self._hosts = frozenset(host.lower() for host in allowed_hosts)
        self._routes = routes

    @property
    def hosts(self) -> frozenset[str]:
        return self._hosts

    @property
    def routes(self) -> frozenset[EgressRoute]:
        return self._routes

    def assert_allowed(self, url: httpx.URL) -> None:
        """Reject ``url`` unless it is https, has no userinfo, and matches an allowed host + route."""
        if url.scheme != "https":
            raise EgressNotAllowed(f"scheme not allowed: {url.scheme!r} (https required)")
        if url.userinfo:
            raise EgressNotAllowed("url must not contain userinfo")
        host = (url.host or "").lower()
        if not host:
            raise EgressNotAllowed("outbound url has no host")
        if host not in self._hosts:
            raise EgressNotAllowed(f"host not on egress allowlist: {host}")
        port = url.port or _DEFAULT_HTTPS_PORT
        route = EgressRoute(ALLOWED_METHOD, host, port, url.path)
        if route not in self._routes:
            raise EgressNotAllowed(f"route not allowed: {ALLOWED_METHOD} {host}:{port}{url.path}")


def assert_host_allowed(url: str, allowlist: frozenset[str]) -> None:
    """Coarse build-time check: reject ``url`` unless it is https, has no userinfo, and its host is on ``allowlist``."""
    parsed = httpx.URL(url)
    if parsed.scheme != "https":
        raise EgressNotAllowed(f"scheme not allowed: {parsed.scheme!r} (https required)")
    if parsed.userinfo:
        raise EgressNotAllowed("url must not contain userinfo")
    host = (parsed.host or "").lower()
    if not host:
        raise EgressNotAllowed("outbound url has no host")
    if host not in allowlist:
        raise EgressNotAllowed(f"host not on egress allowlist: {host}")


def _ip_is_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """True for any address an outbound tool must never reach (SSRF: internal/metadata ranges)."""
    # Unwrap IPv4-mapped IPv6 (e.g. ::ffff:10.0.0.1) so an embedded private IP can't evade the checks.
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return (
        ip.is_private  # 10/8, 172.16/12, 192.168/16, fc00::/7 (unique-local) ...
        or ip.is_loopback  # 127/8, ::1
        or ip.is_link_local  # 169.254/16 (incl. cloud metadata 169.254.169.254), fe80::/10
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified  # 0.0.0.0, ::
    )


def resolve_safe_ip(host: str, port: int | None) -> str:
    """Resolve ``host`` and return ONE validated public IP, or fail closed.

    Fail-closed: a resolution error, no addresses, or **any** address in a blocked range refuses the
    request (the last guards split-horizon DNS that returns both a public and an internal address).
    """
    try:
        infos = socket.getaddrinfo(host, port or _DEFAULT_HTTPS_PORT, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise EgressNotAllowed(f"could not resolve host: {host}") from exc
    if not infos:
        raise EgressNotAllowed(f"no addresses for host: {host}")
    safe_ip: str | None = None
    for info in infos:
        ip_str = str(info[4][0]).split("%", 1)[0]  # strip any IPv6 scope id
        if _ip_is_blocked(ipaddress.ip_address(ip_str)):
            raise EgressNotAllowed(f"host resolves to a blocked address: {ip_str}")
        if safe_ip is None:
            safe_ip = ip_str
    if safe_ip is None:  # defensive: non-empty infos with no blocked IP always selects one
        raise EgressNotAllowed(f"no usable address for host: {host}")
    return safe_ip


class Transport(abc.ABC):
    """Provider-agnostic outbound JSON transport contract."""

    @abc.abstractmethod
    def post_json(self, url: str, *, json: dict[str, Any], access_token: str) -> dict[str, Any]:
        """POST ``json`` to ``url`` with a bearer token; return the decoded JSON object."""
        raise NotImplementedError


class HttpxTransport(Transport):
    """SSRF-hardened sync httpx POST. One parsed URL drives validation, resolution, and the send."""

    def __init__(
        self, policy: EgressPolicy, *, timeout: float = DEFAULT_EGRESS_TIMEOUT_SECONDS
    ) -> None:
        self._policy = policy
        self._timeout = timeout

    def prepare_pinned(self, url: str) -> tuple[httpx.URL, dict[str, str], dict[str, Any]]:
        """Validate + resolve ``url`` and return the pinned (url, headers, extensions) to connect with.

        The returned URL points at the validated IP; the ``Host`` header and ``sni_hostname`` extension
        preserve the original hostname for routing + TLS verification (connect under the same
        interpretation that was validated). Pure except for the single DNS resolution.
        """
        parsed = httpx.URL(url)  # parse ONCE — the single authority for every stage below
        self._policy.assert_allowed(parsed)
        ip = resolve_safe_ip(parsed.host, parsed.port)
        pinned = parsed.copy_with(host=ip)
        host_header = parsed.host
        if parsed.port is not None:
            host_header = f"{parsed.host}:{parsed.port}"
        headers = {"Host": host_header}
        # httpcore (httpx>=0.28) maps extensions["sni_hostname"] to start_tls(server_hostname=...),
        # which ssl.wrap_bio uses for both SNI and certificate hostname verification (not the pinned IP).
        extensions: dict[str, Any] = {"sni_hostname": parsed.host}
        return pinned, headers, extensions

    def post_json(self, url: str, *, json: dict[str, Any], access_token: str) -> dict[str, Any]:
        pinned, headers, extensions = self.prepare_pinned(url)
        headers["Authorization"] = f"Bearer {access_token}"
        with httpx.Client(timeout=self._timeout) as client:
            response = client.post(
                pinned,
                json=json,
                headers=headers,
                extensions=extensions,
                follow_redirects=False,  # never auto-follow to a URL that was never validated
            )
        if response.is_redirect:
            raise EgressNotAllowed(f"redirect not allowed (status {response.status_code})")
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise RuntimeError("provider response was not a JSON object")
        return data


class FakeTransport(Transport):
    """Records outbound calls; never touches the network. Enforces the host allowlist (parity).

    A test double for offline demos/tests — it deliberately does NOT do DNS/IP/route checks (those are
    the real transport's job and are tested directly). ``response`` is the canned provider JSON;
    ``fail=True`` simulates an egress failure so degrade/idempotency paths stay testable offline.
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
