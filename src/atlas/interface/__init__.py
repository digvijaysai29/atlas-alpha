"""Interface layer (M3.2) — a FastAPI HTTP surface over the compiled agent.

Exposes ``/chat`` (start a turn), ``/approve`` (resume a paused approval) and ``/threads/{id}``
(read a thread), with **resume-time principal/thread binding** as the headline security control. See
:mod:`atlas.interface.security` for the (interim, trusted-network) identity model.
"""

from atlas.interface.app import create_app

__all__ = ["create_app"]
