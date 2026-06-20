"""Per-principal rate limiting for the HTTP interface (M3.6).

A thin, swappable wrapper over **Upstash** (managed serverless Redis) via the ``upstash-ratelimit``
SDK — no hand-rolled limiter algorithm to maintain, and because every key carries a Redis window
**TTL** there is no unbounded in-process memory growth.

Design notes (consistent with the rest of the interface layer):

- **Pluggable.** :class:`RateLimiter` is an ABC; :func:`build_rate_limiter` selects the concrete
  backend from :class:`~atlas.config.Settings`. Tests inject a stub through ``create_app`` so the 429
  path is exercised hermetically (no network), exactly like the rest of ``tests/test_interface.py``.
- **Disabled by default in dev/CI.** When Upstash creds are absent (``settings.rate_limit_configured``
  is False) the factory returns ``None`` and the interface is unthrottled — same behavior as before
  M3.6.
- **Fail-open.** Rate limiting is an *availability* control layered **after** authentication and
  authorization; it never grants access. A limiter/backend outage must never take down the API, so
  :meth:`UpstashRateLimiter.acquire` allows the request on any backend error.
- **Interface-only.** Nothing here is checkpointed graph state, so it is deliberately **not** in the
  ``atlas_serde()`` allowlist.
"""

from __future__ import annotations

import abc
import logging
import time
from math import ceil
from typing import TYPE_CHECKING

from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict

from atlas.config import Settings
from atlas.governance.rbac import Principal
from atlas.interface.security import RequestPrincipal

if TYPE_CHECKING:
    from upstash_ratelimit import Ratelimit

logger = logging.getLogger("atlas.interface")


class RateLimitDecision(BaseModel):
    """The outcome of a single rate-limit check. Immutable."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    # Seconds the caller should wait before retrying (0.0 when allowed). Used for the Retry-After header.
    retry_after: float = 0.0


class RateLimiter(abc.ABC):
    """A per-key request limiter. Concrete backends implement :meth:`acquire`."""

    @abc.abstractmethod
    def acquire(self, key: str) -> RateLimitDecision:
        """Consume one unit of budget for ``key`` and report whether the request may proceed."""
        raise NotImplementedError


class UpstashRateLimiter(RateLimiter):
    """Rate limiter backed by Upstash Redis via :class:`upstash_ratelimit.Ratelimit`."""

    def __init__(self, ratelimit: Ratelimit) -> None:
        self._ratelimit = ratelimit

    def acquire(self, key: str) -> RateLimitDecision:
        # Fail-open: a rate-limiter outage is an availability problem, not an authorization one — it
        # must never block legitimate traffic. On any backend/network error we allow and log.
        try:
            response = self._ratelimit.limit(key)
        except Exception:
            logger.exception("Rate limiter backend error; allowing request (fail-open)")
            return RateLimitDecision(allowed=True)
        if response.allowed:
            return RateLimitDecision(allowed=True)
        # `reset` is a Unix timestamp in MILLISECONDS for when the window clears.
        retry_after = max(0.0, response.reset / 1000.0 - time.time())
        return RateLimitDecision(allowed=False, retry_after=retry_after)


def build_rate_limiter(settings: Settings) -> RateLimiter | None:
    """Return the configured limiter, or ``None`` when rate limiting is off (fail-open dev/CI default).

    ``None`` is returned when limiting is disabled or the Upstash creds are absent
    (``settings.rate_limit_configured``). Imports are local so the SDK is only required when actually
    used.
    """
    if not settings.rate_limit_configured:
        return None
    from upstash_ratelimit import FixedWindow, Ratelimit
    from upstash_redis import Redis

    # rate_limit_configured guarantees both are present; guard explicitly to narrow for the type
    # checker (and fail loudly rather than silently mis-build if that invariant ever changes).
    url = settings.upstash_redis_rest_url
    secret = settings.upstash_redis_rest_token
    if url is None or secret is None:  # pragma: no cover - unreachable given rate_limit_configured
        raise RuntimeError("Upstash creds missing despite rate_limit_configured being True.")
    redis = Redis(url=url, token=secret.get_secret_value())
    ratelimit = Ratelimit(
        redis=redis,
        limiter=FixedWindow(
            max_requests=settings.rate_limit_requests,
            window=settings.rate_limit_window_seconds,
        ),
        prefix="atlas/ratelimit",
    )
    return UpstashRateLimiter(ratelimit)


def rate_limit_key(principal: Principal, request: Request) -> str:
    """The bucket key for a request: per identified principal, or per client IP for anonymous.

    Anonymous (the dev header-shim "no verified identity") callers are keyed by client IP so one noisy
    source can't exhaust a single shared bucket and starve other anonymous callers.
    """
    if principal == Principal.anonymous():
        client = request.client
        return f"ip|{client.host if client else 'unknown'}"
    return f"u|{principal.org_id}|{principal.user_id}"


def enforce_rate_limit(request: Request, principal: RequestPrincipal) -> None:
    """FastAPI dependency: 429 when the caller is over budget (no-op when limiting is disabled).

    Depends on :data:`~atlas.interface.security.RequestPrincipal` so identity is resolved (and an
    invalid token already 401s) **before** the limit is consulted — limiting never precedes authn.
    """
    limiter: RateLimiter | None = getattr(request.app.state, "rate_limiter", None)
    if limiter is None:
        return  # rate limiting disabled / unconfigured
    decision = limiter.acquire(rate_limit_key(principal, request))
    if not decision.allowed:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Rate limit exceeded.",
            headers={"Retry-After": str(ceil(decision.retry_after))},
        )


# A route-level dependency: `dependencies=[RateLimited]` on /chat and /approve.
RateLimited = Depends(enforce_rate_limit)
