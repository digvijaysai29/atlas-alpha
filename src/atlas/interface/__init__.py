"""Interface layer (M3.2) — a FastAPI HTTP surface over the compiled agent.

Exposes ``/chat`` (start a turn), ``/chat/stream`` (M4.7 — the same turn delivered as Server-Sent
Events), ``/approve`` (resume a paused approval) and ``/threads/{id}`` (read a thread), with
**resume-time principal/thread binding** as the headline security control. See
:mod:`atlas.interface.security` for the (interim, trusted-network) identity model.
"""

from atlas.interface.app import create_app
from atlas.interface.rate_limit import RateLimiter, build_rate_limiter

__all__ = ["create_app", "RateLimiter", "build_rate_limiter"]
