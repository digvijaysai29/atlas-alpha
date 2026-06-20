"""Rate-limiting tests (offline, hermetic) for the M3.6 interface throttle.

The 429 path is exercised by **injecting a stub** :class:`~atlas.interface.rate_limit.RateLimiter`
into ``create_app`` (the same DI used by ``tests/test_interface.py``) — no Upstash account or network
is needed in CI. A real Upstash round-trip is an opt-in ``-m integration`` test gated on the env
creds (mirroring the Postgres integration pattern).
"""

from __future__ import annotations

import os
import time

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from atlas.actions import ProposedAction
from atlas.config import Settings
from atlas.governance.rbac import Principal
from atlas.interface import create_app
from atlas.interface.rate_limit import (
    RateLimiter,
    RateLimitDecision,
    build_rate_limiter,
    rate_limit_key,
)
from atlas.orchestration import build_graph
from atlas.orchestration.graph import Atlas
from atlas.orchestration.nodes import PlanFn
from atlas.orchestration.serde import atlas_serde
from atlas.tools import ToolRegistry

from langgraph.checkpoint.memory import InMemorySaver


# --- stubs -------------------------------------------------------------------
class _CountingLimiter(RateLimiter):
    """Allows the first ``limit`` calls per key, then denies with a fixed retry_after."""

    def __init__(self, limit: int, *, retry_after: float = 30.0) -> None:
        self._limit = limit
        self._retry_after = retry_after
        self._counts: dict[str, int] = {}

    def acquire(self, key: str) -> RateLimitDecision:
        self._counts[key] = self._counts.get(key, 0) + 1
        if self._counts[key] > self._limit:
            return RateLimitDecision(allowed=False, retry_after=self._retry_after)
        return RateLimitDecision(allowed=True)


def _send_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("send_email", {"to": "a@b.com", "subject": "hi", "body": "x"})]


def _search_plan(_req: str, registry: ToolRegistry, _ctx: object) -> list[ProposedAction]:
    return [registry.propose("search", {"query": "x"})]


def _build(plan_fn: PlanFn, limiter: RateLimiter | None) -> tuple[TestClient, Atlas]:
    atlas = build_graph(plan_fn=plan_fn, checkpointer=InMemorySaver(serde=atlas_serde()))
    app = create_app(atlas=atlas, settings=Settings(ANTHROPIC_API_KEY=None), rate_limiter=limiter)
    return TestClient(app), atlas


def _headers(user: str, roles: str = "member", org: str | None = None) -> dict[str, str]:
    h = {"X-Atlas-User-Id": user, "X-Atlas-Roles": roles}
    if org is not None:
        h["X-Atlas-Org"] = org
    return h


# --- rate_limit_key ----------------------------------------------------------
class _FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class _FakeRequest:
    def __init__(self, host: str | None) -> None:
        self.client = _FakeClient(host) if host is not None else None


def test_key_for_identified_principal() -> None:
    p = Principal(user_id="alice", roles=("member",), org_id="acme")
    key = rate_limit_key(p, _FakeRequest("1.2.3.4"))  # type: ignore[arg-type]
    assert key.startswith("u|")
    assert len(key) == 66  # "u|" + 64-char SHA-256 hex


def test_none_org_id_differs_from_literal_none_string() -> None:
    none_org = Principal(user_id="alice", roles=(), org_id=None)
    literal_none = Principal(user_id="alice", roles=(), org_id="None")
    assert rate_limit_key(none_org, _FakeRequest("x")) != rate_limit_key(  # type: ignore[arg-type]
        literal_none, _FakeRequest("x")  # type: ignore[arg-type]
    )


def test_delimiter_in_ids_does_not_collide() -> None:
    a = Principal(user_id="b|c", roles=(), org_id="a")
    b = Principal(user_id="c", roles=(), org_id="a|b")
    assert rate_limit_key(a, _FakeRequest("x")) != rate_limit_key(b, _FakeRequest("x"))  # type: ignore[arg-type]


def test_key_for_anonymous_uses_client_ip() -> None:
    key = rate_limit_key(Principal.anonymous(), _FakeRequest("9.9.9.9"))  # type: ignore[arg-type]
    assert key == "ip|9.9.9.9"


def test_key_for_anonymous_without_client_is_unknown() -> None:
    key = rate_limit_key(Principal.anonymous(), _FakeRequest(None))  # type: ignore[arg-type]
    assert key == "ip|unknown"


def test_distinct_users_do_not_share_a_key() -> None:
    a = Principal(user_id="alice", roles=(), org_id="acme")
    b = Principal(user_id="bob", roles=(), org_id="acme")
    assert rate_limit_key(a, _FakeRequest("x")) != rate_limit_key(b, _FakeRequest("x"))  # type: ignore[arg-type]


# --- enforcement via the dependency (injected stub) --------------------------
def test_chat_429s_after_limit_with_envelope_and_retry_after() -> None:
    client, _ = _build(_search_plan, _CountingLimiter(limit=2))
    h = _headers("alice")
    assert client.post("/chat", json={"message": "find"}, headers=h).status_code == 200
    assert client.post("/chat", json={"message": "find"}, headers=h).status_code == 200
    resp = client.post("/chat", json={"message": "find"}, headers=h)
    assert resp.status_code == 429
    body = resp.json()
    assert body["ok"] is False
    assert body["error"]["code"] == "too_many_requests"
    assert resp.headers.get("Retry-After") == "30"


def test_limit_is_per_principal() -> None:
    client, _ = _build(_search_plan, _CountingLimiter(limit=1))
    # alice exhausts her own bucket...
    assert client.post("/chat", json={"message": "f"}, headers=_headers("alice")).status_code == 200
    assert client.post("/chat", json={"message": "f"}, headers=_headers("alice")).status_code == 429
    # ...bob is unaffected (independent key).
    assert client.post("/chat", json={"message": "f"}, headers=_headers("bob")).status_code == 200


def test_approve_is_rate_limited() -> None:
    client, _ = _build(_send_plan, _CountingLimiter(limit=1))
    # The single allowed call is consumed by /chat, so /approve is over budget => 429.
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    resp = client.post(
        "/approve", json={"thread_id": tid, "approve": True}, headers=_headers("alice")
    )
    assert resp.status_code == 429


def test_healthz_is_not_rate_limited() -> None:
    client, _ = _build(_search_plan, _CountingLimiter(limit=0))  # deny everything that is limited
    assert client.get("/healthz").status_code == 200


def test_threads_read_is_not_rate_limited() -> None:
    # A limiter that allows exactly one call (the /chat) — the subsequent /threads read must NOT 429.
    client, _ = _build(_send_plan, _CountingLimiter(limit=1))
    tid = client.post("/chat", json={"message": "email"}, headers=_headers("alice")).json()[
        "thread_id"
    ]
    assert client.get(f"/threads/{tid}", headers=_headers("alice")).status_code == 200


def test_disabled_when_no_limiter() -> None:
    client, _ = _build(_search_plan, None)
    for _ in range(5):
        assert (
            client.post("/chat", json={"message": "f"}, headers=_headers("alice")).status_code
            == 200
        )


# --- UpstashRateLimiter fail-open (no network: stub the SDK call) ------------
def test_upstash_limiter_fails_open_on_backend_error() -> None:
    from atlas.interface.rate_limit import UpstashRateLimiter

    class _Boom:
        def limit(self, _key: str) -> object:
            raise RuntimeError("network down")

    limiter = UpstashRateLimiter(_Boom())  # type: ignore[arg-type]
    decision = limiter.acquire("u|acme|alice")
    assert decision.allowed is True  # fail-open: outage must not block traffic


def test_upstash_limiter_maps_denied_response() -> None:
    from atlas.interface.rate_limit import UpstashRateLimiter

    class _Resp:
        allowed = False
        reset = time.time() + 45.7  # seconds until window clears (SDK uses seconds)

    class _RL:
        def limit(self, _key: str) -> object:
            return _Resp()

    decision = UpstashRateLimiter(_RL()).acquire("k")  # type: ignore[arg-type]
    assert decision.allowed is False
    assert 45 <= decision.retry_after <= 46


# --- build_rate_limiter selection -------------------------------------------
def test_build_returns_none_when_unconfigured() -> None:
    assert build_rate_limiter(Settings(ANTHROPIC_API_KEY=None)) is None


def test_build_returns_none_when_disabled_even_with_creds() -> None:
    settings = Settings(
        ANTHROPIC_API_KEY=None,
        ATLAS_RATE_LIMIT_ENABLED=False,
        UPSTASH_REDIS_REST_URL="https://example.upstash.io",
        UPSTASH_REDIS_REST_TOKEN=SecretStr("tok"),
    )
    assert build_rate_limiter(settings) is None


# --- opt-in real Upstash integration (skipped without creds) -----------------
@pytest.mark.integration
@pytest.mark.skipif(
    not (os.getenv("UPSTASH_REDIS_REST_URL") and os.getenv("UPSTASH_REDIS_REST_TOKEN")),
    reason="requires live Upstash REST creds",
)
def test_real_upstash_enforces_limit() -> None:
    settings = Settings(ANTHROPIC_API_KEY=None, ATLAS_RATE_LIMIT_REQUESTS=2)
    limiter = build_rate_limiter(settings)
    assert limiter is not None
    import uuid

    key = f"test|{uuid.uuid4().hex}"  # unique key so reruns don't collide on the window
    assert limiter.acquire(key).allowed is True
    assert limiter.acquire(key).allowed is True
    denied = limiter.acquire(key)
    assert denied.allowed is False
    assert denied.retry_after > 0
