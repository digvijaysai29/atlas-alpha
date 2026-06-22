# syntax=docker/dockerfile:1

FROM python:3.13-slim AS builder

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
COPY src/ src/
COPY scripts/run_api.py scripts/run_api.py

RUN uv sync --frozen --no-dev

FROM python:3.13-slim AS runner

WORKDIR /app

RUN groupadd --gid 1001 atlas     && useradd --uid 1001 --gid 1001 --create-home --shell /usr/sbin/nologin atlas

COPY --from=builder --chown=1001:1001 /app/.venv /app/.venv
COPY --from=builder --chown=1001:1001 /app/pyproject.toml /app/pyproject.toml
COPY --from=builder --chown=1001:1001 /app/src /app/src
COPY --from=builder --chown=1001:1001 /app/scripts/run_api.py /app/scripts/run_api.py

ENV PATH="/app/.venv/bin:$PATH"     PYTHONUNBUFFERED=1     ATLAS_API_HOST=0.0.0.0     ATLAS_API_PORT=8000

USER 1001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3     CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz')" || exit 1

CMD ["python", "scripts/run_api.py"]
