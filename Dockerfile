FROM python:3.15-slim@sha256:65a65fc7b30b06cb6df4930fd4650697cb23f4c2698ab81fc87e4b031bc36928 AS runtime

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
