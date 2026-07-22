#!/usr/bin/env bash
set -Eeuo pipefail

readonly PROJECT_DIR="/home/semeion-tech/cpanel-reseller-mcp"
readonly REGISTRY_IMAGE="ghcr.io/semeion-tech/cpanel-reseller-mcp"
readonly IMAGE="${1:?image is required}"
readonly COMMIT_SHA="${2:?commit SHA is required}"
readonly RUN_ID="${3:?GitHub run ID is required}"
readonly COMPOSE_SOURCE="${4:?staged compose file is required}"
readonly HEALTHCHECK_URL="${5:?health-check URL is required}"
readonly STATE_DIR="$PROJECT_DIR/.deploy"
readonly PREVIOUS_COMPOSE="$STATE_DIR/compose.previous.yaml"
readonly ROLLBACK_IMAGE="$REGISTRY_IMAGE:rollback"

if [[ ! "$COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'invalid commit SHA\n' >&2
  exit 2
fi
if [[ ! "$RUN_ID" =~ ^[0-9]+$ ]]; then
  printf 'invalid GitHub run ID\n' >&2
  exit 2
fi
if [[ "$IMAGE" != "$REGISTRY_IMAGE:sha-$COMMIT_SHA" ]]; then
  printf 'image does not match the immutable commit tag\n' >&2
  exit 2
fi
if [[ ! -f "$COMPOSE_SOURCE" || ! -f "$PROJECT_DIR/.env" ]]; then
  printf 'staged compose file or production environment is missing\n' >&2
  exit 2
fi

install -m 700 -d "$STATE_DIR"
exec 9>"$STATE_DIR/deploy.lock"
if ! flock -n 9; then
  printf 'another production deployment is already running\n' >&2
  exit 3
fi

cd "$PROJECT_DIR"
cp -p compose.yaml "$PREVIOUS_COMPOSE"

current_container="$(docker compose ps -q reseller-mcp 2>/dev/null || true)"
previous_image_id=""
if [[ -n "$current_container" ]]; then
  previous_image_id="$(docker inspect --format '{{.Image}}' "$current_container")"
  docker image tag "$previous_image_id" "$ROLLBACK_IMAGE"
  printf '%s\n' "$ROLLBACK_IMAGE" > "$STATE_DIR/previous-image"

  docker compose exec -T \
    -e BACKUP_PATH=/app/data/pre-deploy.db \
    reseller-mcp python -c \
    'import os, sqlite3; src=sqlite3.connect("/app/data/reseller-mcp.db"); dst=sqlite3.connect(os.environ["BACKUP_PATH"]); src.backup(dst); dst.close(); src.close()'
fi

rollback_required=true
rollback() {
  local exit_code=$?
  trap - EXIT
  if [[ "$rollback_required" == true ]]; then
    printf 'deployment failed; restoring previous compose and image\n' >&2
    install -m 0644 "$PREVIOUS_COMPOSE" compose.yaml
    if docker image inspect "$ROLLBACK_IMAGE" >/dev/null 2>&1; then
      RESELLER_MCP_IMAGE="$ROLLBACK_IMAGE" \
        docker compose up -d --no-build --force-recreate reseller-mcp || true
    else
      docker compose up -d --no-build --force-recreate reseller-mcp || true
    fi
  fi
  exit "$exit_code"
}
trap rollback EXIT

install -m 0644 "$COMPOSE_SOURCE" compose.yaml
RESELLER_MCP_IMAGE="$IMAGE" docker compose pull reseller-mcp
RESELLER_MCP_IMAGE="$IMAGE" \
  docker compose up -d --no-build --remove-orphans reseller-mcp

healthy=false
for _ in $(seq 1 60); do
  container="$(RESELLER_MCP_IMAGE="$IMAGE" docker compose ps -q reseller-mcp)"
  status="$(
    docker inspect \
      --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
      "$container" 2>/dev/null || true
  )"
  if [[ "$status" == healthy ]]; then
    healthy=true
    break
  fi
  if [[ "$status" == exited || "$status" == dead ]]; then
    break
  fi
  sleep 2
done
if [[ "$healthy" != true ]]; then
  RESELLER_MCP_IMAGE="$IMAGE" docker compose logs --tail 100 reseller-mcp >&2 || true
  printf 'container did not become healthy\n' >&2
  exit 1
fi

health_payload="$(curl --fail --silent --show-error --max-time 10 --retry 5 "$HEALTHCHECK_URL")"
python3 -c \
  'import json,sys; payload=json.loads(sys.argv[1]); assert payload.get("status") == "ok"' \
  "$health_payload"

printf '%s\n' "$IMAGE" > "$STATE_DIR/current-image"
printf '%s\n' "$COMMIT_SHA" > "$STATE_DIR/current-commit"
printf '%s\n' "$RUN_ID" > "$STATE_DIR/last-successful-run"
rollback_required=false
printf '{"status":"deployed","image":"%s","commit":"%s","run_id":"%s"}\n' \
  "$IMAGE" "$COMMIT_SHA" "$RUN_ID"
