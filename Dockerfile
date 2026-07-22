FROM python:3.12-slim@sha256:57cd7c3a7a273101a6485ba99423ee568157882804b1124b4dd04266317710de AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PATH="/app/.venv/bin:$PATH"

RUN groupadd --system --gid 10001 reseller-mcp \
    && useradd --system --uid 10001 --gid reseller-mcp --home-dir /app reseller-mcp

WORKDIR /app
COPY pyproject.toml uv.lock README.md ./
COPY src ./src
RUN pip install "uv==0.10.2" \
    && uv sync --frozen --no-dev --no-editable \
    && pip uninstall --yes uv

RUN mkdir -p /app/data && chown -R reseller-mcp:reseller-mcp /app
USER reseller-mcp

EXPOSE 8080
CMD ["reseller-mcp"]
