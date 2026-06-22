# Release validation (local)

Validate the production container image on your machine before tagging or deploying.

## Prerequisites

- Docker installed and running
- Repository root as the build context

## Checklist

1. **Build the image**

   ```bash
   docker build -t atlas:local .
   ```

2. **Run the container**

   ```bash
   docker run -d --name atlas-local -p 8000:8000 atlas:local
   ```

3. **Probe the health endpoint**

   ```bash
   curl -fsS http://127.0.0.1:8000/healthz
   ```

   Expected response: `{"ok": true}` (verified in `tests/test_interface.py`).

4. **Stop the container**

   ```bash
   docker stop atlas-local && docker rm atlas-local
   ```

## Notes

- The image runs **`scripts/run_api.py`** (not **`main.py`**, which is demo-only).
- Bind address defaults to **`0.0.0.0`** inside the container (`ATLAS_API_HOST` in the `Dockerfile`) so `-p 8000:8000` works; local dev via `uv run python scripts/run_api.py` defaults to `127.0.0.1`.
- For durable persistence or live integrations, pass environment variables at run time (e.g. `-e DATABASE_URL=...`). See [`.env.example`](../../.env.example), [`HANDOFF.md`](./HANDOFF.md) §3, and [`AUTH.md`](./AUTH.md) for variable names and semantics.
