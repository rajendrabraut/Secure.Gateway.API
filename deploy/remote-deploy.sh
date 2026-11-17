#!/usr/bin/env bash
# Runs ON the target host (streamed over SSH by .github/workflows/_deploy.yml).
# Required env: ENVIRONMENT (staging|production), VERSION, IMAGE_REPO (lowercase owner/repo), PORT.
# Runtime config lives in ~/secure-gateway/<ENVIRONMENT>.env (docker --env-file format, mode 600).
set -euo pipefail

: "${ENVIRONMENT:?}" "${VERSION:?}" "${IMAGE_REPO:?}" "${PORT:?}"

name="secure-gateway-${ENVIRONMENT}"
previous="${name}-previous"
image="ghcr.io/${IMAGE_REPO}:${VERSION}"
envfile="${HOME}/secure-gateway/${ENVIRONMENT}.env"

command -v docker >/dev/null || { echo "::error::docker is not installed on the host"; exit 1; }
command -v curl >/dev/null || { echo "::error::curl is not installed on the host"; exit 1; }
[[ -f "$envfile" ]] || { echo "::error::missing $envfile (set the GATEWAY_ENV_FILE secret or create it on the host)"; exit 1; }

# The health probe must send a Host header that AllowedHosts accepts.
hosts="$(grep -E '^AllowedHosts=' "$envfile" | head -n1 | cut -d= -f2- | cut -d';' -f1 || true)"
probe_host="${hosts:-localhost}"
[[ "$probe_host" == "*" ]] && probe_host="localhost"
probe_host="${probe_host/#\*./health.}"

echo "Pulling ${image}"
docker pull --quiet "$image" >/dev/null

# Keep the running container as a rollback target.
docker rm -f "$previous" >/dev/null 2>&1 || true
had_previous=false
if docker inspect "$name" >/dev/null 2>&1; then
  had_previous=true
  docker stop --time 20 "$name" >/dev/null
  docker rename "$name" "$previous"
fi

echo "Starting ${name}"
docker run -d \
  --name "$name" \
  --restart unless-stopped \
  --publish "${PORT}:8080" \
  --env-file "$envfile" \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 512 \
  --label "app.version=${VERSION}" \
  "$image" >/dev/null

healthy=false
for _ in $(seq 1 40); do
  if curl -fsS -m 3 -H "Host: ${probe_host}" "http://127.0.0.1:${PORT}/health/ready" >/dev/null 2>&1; then
    healthy=true
    break
  fi
  [[ "$(docker inspect -f '{{.State.Running}}' "$name")" == "true" ]] || break
  sleep 3
done

if [[ "$healthy" == "true" ]]; then
  echo "Healthy: ${name} is running ${VERSION}"
  docker rm -f "$previous" >/dev/null 2>&1 || true
  docker image prune -f --filter "until=168h" >/dev/null 2>&1 || true
  exit 0
fi

echo "::error::${name} failed its health check; last logs follow"
docker logs --tail 50 "$name" 2>&1 || true
docker rm -f "$name" >/dev/null 2>&1 || true
if [[ "$had_previous" == "true" ]]; then
  docker rename "$previous" "$name"
  docker start "$name" >/dev/null
  echo "::warning::Rolled back to the previous container"
fi
exit 1
