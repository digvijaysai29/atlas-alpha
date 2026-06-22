# syntax=docker/dockerfile:1

FROM python:3.13-slim@sha256:3a2c25932e66f706172de831a1b283d491c53ef876cd7fc55a62bcf9a6dd2c61 AS builder

COPY --from=ghcr.io/astral-sh/uv:0.7.6@sha256:e4a23f59ca0e088a60de23d34e95ca272630db213fe9a48d1d5d4dc014ba64a8 /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
COPY scripts/run_api.py scripts/run_api.py

RUN uv sync --frozen --no-dev

FROM python:3.13-slim@sha256:3a2c25932e66f706172de831a1b283d491c53ef876cd7fc55a62bcf9a6dd2c61 AS runner

WORKDIR /app

RUN groupadd --gid 1001 atlas     && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin atlas

COPY --from=builder --chown=1001:1001 /app/.venv /app/.venv
COPY --from=builder --chown=1001:1001 /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=1001:1001 /app/src /app/src
COPY --from=builder --chown=1001:1001 /app/scripts/run_api.py /app/scripts/run_api.py

ENV PATH="/app/.venv/bin:$PATH"     PYTHONUNBUFFERED=1     ATLAS_API_HOST=0.0.0.0     ATLAS_API_PORT=8000

USER 1001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.getenv('ATLAS_API_PORT', '8000')}/healthz\")" || exit 1

CMD ["python", "scripts/run_api.py"]
