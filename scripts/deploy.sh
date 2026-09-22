#!/usr/bin/env bash
# deploy.sh <tier> <image> — deploy a NodeGoat image to one tier on the lab VM
# and wait until it responds. Used by the deploy workflows; also runnable by hand.
set -euo pipefail

tier=${1:?usage: deploy.sh <dev|prod> <image>}
image=${2:?usage: deploy.sh <dev|prod> <image>}

root=$(cd "$(dirname "$0")/.." && pwd)
env_file="$root/deploy/env/$tier.env"
[[ -f $env_file ]] || { echo "unknown tier: $tier" >&2; exit 1; }
# shellcheck source=/dev/null
source "$env_file"

export NODEGOAT_IMAGE=$image
compose=(docker compose -f "$root/deploy/compose.yaml" --env-file "$env_file")

"${compose[@]}" pull web
"${compose[@]}" up -d --remove-orphans

# NodeGoat only serves once Mongo is up and the seed script has run. Poll rather than sleep.
for _ in $(seq 1 30); do
  if curl -sf -o /dev/null "http://127.0.0.1:$APP_PORT/login"; then
    echo "$tier is up on 127.0.0.1:$APP_PORT running $image"
    exit 0
  fi
  sleep 5
done

echo "$tier did not respond on 127.0.0.1:$APP_PORT" >&2
"${compose[@]}" logs --tail 50 web >&2
exit 1
