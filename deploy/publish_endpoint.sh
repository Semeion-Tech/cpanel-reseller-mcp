#!/usr/bin/env bash
set -euo pipefail

: "${DOMAIN:?set the public MCP domain}"
: "${ZONE_ID:?set the Cloudflare zone ID}"
: "${PUBLIC_IP:?set the public IPv4 address}"
PROJECT_DIR="${PROJECT_DIR:-/home/semeion-tech/cpanel-reseller-mcp}"
CLOUDFLARE_ENV_FILE="${CLOUDFLARE_ENV_FILE:-/root/.cloudflare.env}"

set -a
# shellcheck source=/dev/null
. "$CLOUDFLARE_ENV_FILE"
set +a
: "${CLOUDFLARE_API_TOKEN:?missing Cloudflare API token}"

API="https://api.cloudflare.com/client/v4/zones/${ZONE_ID}/dns_records"
AUTH_HEADER="Authorization: Bearer ${CLOUDFLARE_API_TOKEN}"
RECORD_ID="$(
  curl -4 -fsS -H "$AUTH_HEADER" "${API}?type=A&name=${DOMAIN}" \
    | python3 -c 'import json,sys; r=json.load(sys.stdin).get("result",[]); print(r[0]["id"] if r else "")'
)"
PAYLOAD="$(
  python3 -c 'import json,sys; print(json.dumps({"type":"A","name":sys.argv[1],"content":sys.argv[2],"ttl":300,"proxied":False}))' \
    "$DOMAIN" "$PUBLIC_IP"
)"
if [[ -n "$RECORD_ID" ]]; then
  curl -4 -fsS -X PUT -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    --data "$PAYLOAD" "${API}/${RECORD_ID}" >/dev/null
else
  curl -4 -fsS -X POST -H "$AUTH_HEADER" -H "Content-Type: application/json" \
    --data "$PAYLOAD" "$API" >/dev/null
fi

certbot certonly \
  --manual \
  --preferred-challenges dns \
  --manual-auth-hook /root/scripts/certbot-cloudflare-auth.sh \
  --manual-cleanup-hook /root/scripts/certbot-cloudflare-cleanup.sh \
  --domain "$DOMAIN" \
  --cert-name "$DOMAIN" \
  --non-interactive \
  --agree-tos

install -m 0644 "$PROJECT_DIR/deploy/nginx.conf.example" \
  "/etc/nginx/conf.d/domains/${DOMAIN}.conf"
nginx -t
systemctl reload nginx
printf '{"status":"published","domain":"%s","ip":"%s"}\n' "$DOMAIN" "$PUBLIC_IP"
