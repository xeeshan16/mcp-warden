# syntax=docker/dockerfile:1

# --- build: resolve the locked dependencies into a virtual environment --------
FROM python:3.12-slim AS build

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/app/.venv

RUN pip install --no-cache-dir uv==0.11.32

WORKDIR /src
# Dependencies first, so editing the source does not invalidate this layer.
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev --no-install-project --extra postgres --extra otel

COPY README.md LICENSE ./
COPY src ./src
RUN uv sync --locked --no-dev --no-editable --extra postgres --extra otel

# --- runtime: the virtual environment and the example configuration only ------
FROM python:3.12-slim

LABEL org.opencontainers.image.title="mcp-warden" \
      org.opencontainers.image.description="Policy, budget and audit gateway for MCP tool calls" \
      org.opencontainers.image.source="https://github.com/xeeshan16/mcp-warden" \
      org.opencontainers.image.licenses="MIT"

RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin warden

COPY --from=build /app/.venv /app/.venv
COPY examples /app/examples

WORKDIR /app
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    WARDEN_HOST=0.0.0.0 \
    WARDEN_PORT=8080

USER 10001
EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=10s --retries=10 \
    CMD ["python", "-c", "import os, urllib.request; urllib.request.urlopen(f\"http://127.0.0.1:{os.environ.get('WARDEN_PORT', '8080')}/healthz\", timeout=2)"]

ENTRYPOINT ["mcp-warden"]
CMD ["serve"]
