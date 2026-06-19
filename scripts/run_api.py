"""Run the atlas HTTP interface (dev server).

  uv run python scripts/run_api.py

Then, with the trusted-network identity headers (DEV ONLY — see atlas.interface.security):

  curl -s -XPOST localhost:8000/chat \
    -H 'X-Atlas-User-Id: alice' -H 'X-Atlas-Roles: member' \
    -H 'content-type: application/json' -d '{"message":"email a@b.com the status update"}'
  # -> {"status":"awaiting_approval","thread_id":"thr_...","pending_actions":[...]}

  curl -s -XPOST localhost:8000/approve \
    -H 'X-Atlas-User-Id: alice' -H 'X-Atlas-Roles: member' \
    -H 'content-type: application/json' -d '{"thread_id":"thr_...","approve":true}'
  # Approving as a DIFFERENT user (e.g. X-Atlas-User-Id: bob) returns 403 (resume-time binding).
"""

from __future__ import annotations

import uvicorn

from atlas.config import get_settings
from atlas.interface import create_app


def main() -> None:
    settings = get_settings()
    app = create_app(settings=settings)
    uvicorn.run(app, host=settings.api_host, port=settings.api_port)


if __name__ == "__main__":
    main()
