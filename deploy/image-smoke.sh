#!/bin/sh
# Smoke test of a built keymesh-web image (CI image legs, before any push):
# runs it with the same hardening as deploy/compose.yaml (read-only, no
# capabilities, no-new-privileges, uid 1000, memory and pids limits), waits for
# the image's own HEALTHCHECK to report healthy, checks that it serves the app
# with its security headers, and that the runtime holds no package manager.
#
#   sh deploy/image-smoke.sh <image>
set -eu

IMAGE=${1:?usage: $0 <image>}
NAME=keymesh-web-smoke
fail() { printf '::error::image smoke test: %s\n' "$*" >&2; docker logs "$NAME" 2>&1 | tail -n 20 >&2 || true; exit 1; }
cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker run -d --name "$NAME" --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --user 1000:1000 --memory 256m --memory-swap 256m --pids-limit 64 "$IMAGE" >/dev/null

status=starting
i=0
while [ $i -lt 60 ]; do
  status=$(docker inspect --format '{{ .State.Health.Status }}' "$NAME")
  [ "$status" = healthy ] && break
  [ "$status" = unhealthy ] && fail "container reported unhealthy"
  sleep 2
  i=$((i + 1))
done
[ "$status" = healthy ] || fail "not healthy after 120 s (last: $status)"
echo "health: $status"

# Served by the container itself (loopback inside it).
docker exec "$NAME" node -e "
fetch('http://127.0.0.1:4320/').then(async (r) => {
  const csp = r.headers.get('content-security-policy') || '';
  const body = await r.text();
  if (r.status !== 200) throw new Error('status ' + r.status);
  if (!csp.includes(\"default-src 'self'\")) throw new Error('missing CSP');
  if (r.headers.get('x-content-type-options') !== 'nosniff') throw new Error('missing nosniff');
  if (!body.includes('<app-root>')) throw new Error('not the app shell');
  console.log('serves the app shell with CSP and nosniff');
}).catch((e) => { console.error(e.message); process.exit(1); });
" || fail "the app is not served as expected"

# No package manager or global modules in the runtime; unprivileged user.
docker exec "$NAME" sh -c '
  for t in npm npx corepack yarn yarnpkg; do if command -v "$t" >/dev/null 2>&1; then echo "found $t"; exit 1; fi; done
  if [ -e /usr/local/lib/node_modules ]; then echo "found /usr/local/lib/node_modules"; exit 1; fi
  [ "$(id -u)" = 1000 ] || { echo "uid $(id -u)"; exit 1; }
' || fail "runtime is not minimal or not unprivileged"
echo "no npm, npx, corepack or yarn; uid 1000"
echo "image smoke test passed: $IMAGE"
