#!/bin/sh
# Deploy a CI-built keymesh-web image on the Pi (see deploy/README.md).
#
#   KEYMESH_IMAGE_REPO=<namespace>/keymesh-web \
#     deploy/pull-deploy.sh <full 40-hex commit sha> [<namespace>/keymesh-web]
#
# 1. Pulls docker.io/<repo>:sha-<sha> and pins it by digest.
# 2. Refuses unless the revision label is <sha> and the platform is linux/arm64.
# 3. Verifies the build provenance with `gh attestation verify` when gh is installed.
# 4. Copies the bundle out of the image and prints sha256 of the key files
#    (and compares every file with a CI asset ledger when KEYMESH_LEDGER is set).
# 5. Tags the current web image keymesh-web:rollback-<old revision>.
# 6. Recreates ONLY the web service (--no-deps --no-build) from the digest.
# 7. Waits for it to be healthy; otherwise rolls back and exits non-zero.
#
# It never touches the host's reverse proxy, certificates, DNS, VPN or firewall,
# and never sets KEYMESH_FAVICON. Running it again with the same sha
# is a no-op once that image is running and healthy.
#
# Environment:
#   KEYMESH_IMAGE_REPO          Docker Hub repository <namespace>/<name>, the value of the
#                               DOCKERHUB_REPOSITORY variable in CI (or the 2nd argument)
#   KEYMESH_VERIFY_ATTESTATION  auto (default: verify when gh exists) | 1 (require) | 0 (skip)
#   KEYMESH_LEDGER              optional path to the CI asset-ledger.json (needs node)
#   KEYMESH_HEALTH_TIMEOUT      seconds to wait for healthy (default 150)
#   SUDO                        command prefix for docker (default "sudo"; empty if root)
#   KEYMESH_IMAGE_REGISTRY      registry host (default docker.io; override only for local testing)
set -eu

REGISTRY=${KEYMESH_IMAGE_REGISTRY:-docker.io}
ATTEST_REPO=flarexio/keymesh
PLATFORM=linux/arm64
SUDO=${SUDO-sudo}
VERIFY=${KEYMESH_VERIFY_ATTESTATION:-auto}
TIMEOUT=${KEYMESH_HEALTH_TIMEOUT:-150}
HERE=$(cd "$(dirname "$0")" && pwd)
COMPOSE_FILE=$HERE/compose.yaml

log() { printf 'pull-deploy: %s\n' "$*"; }
die() { printf 'pull-deploy: ERROR: %s\n' "$*" >&2; exit 1; }

# $SUDO is intentionally unquoted: empty means "no prefix".
# shellcheck disable=SC2086
d() { $SUDO docker "$@"; }
# compose <web image> <args...>: web is the only service, and it is always named.
# shellcheck disable=SC2086
compose() {
  img=$1
  shift
  $SUDO env KEYMESH_WEB_IMAGE="$img" docker compose -f "$COMPOSE_FILE" "$@"
}
label() { d image inspect --format "{{ index .Config.Labels \"$2\" }}" "$1"; }
web_container() {
  d ps -aq --filter label=com.docker.compose.project=keymesh \
    --filter label=com.docker.compose.service=web | head -n 1
}
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$@"; else shasum -a 256 "$@"; fi; }

# wait_healthy <container> : 0 when healthy, 1 when unhealthy/exited/timed out.
wait_healthy() {
  waited=0
  while [ "$waited" -lt "$TIMEOUT" ]; do
    state=$(d inspect --format '{{ .State.Status }} {{ if .State.Health }}{{ .State.Health.Status }}{{ else }}none{{ end }}' "$1") || return 1
    case $state in
      'running healthy') return 0 ;;
      *unhealthy | exited* | dead* | 'running none') log "web state: $state"; return 1 ;;
    esac
    sleep 3
    waited=$((waited + 3))
  done
  log "web not healthy after ${TIMEOUT}s (last state: $state)"
  return 1
}

# recreate_web <image ref> : recreate only web from a local image, then wait.
recreate_web() {
  compose "$1" up -d --no-deps --no-build --pull never --force-recreate web
  cid=$(web_container)
  [ -n "$cid" ] || return 1
  wait_healthy "$cid"
}

# --- arguments ---------------------------------------------------------------
[ $# -eq 1 ] || [ $# -eq 2 ] || die "usage: $0 <full 40-hex commit sha> [<namespace>/<name>]"
SHA=$1
NAME=${2:-${KEYMESH_IMAGE_REPO:-}}
printf '%s' "$NAME" | grep -Eqx '[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*' ||
  die "set KEYMESH_IMAGE_REPO (or pass it as the 2nd argument) to <namespace>/<name>: '$NAME'"
REPO=$REGISTRY/$NAME
case $SHA in *[!0-9a-f]* | '') die "commit sha must be lowercase hex: $SHA" ;; esac
[ ${#SHA} -eq 40 ] || die "commit sha must be the full 40 characters: $SHA"
case $VERIFY in auto | 0 | 1) ;; *) die "KEYMESH_VERIFY_ATTESTATION must be auto, 0 or 1" ;; esac
REF=$REPO:sha-$SHA

# --- 1. pull and pin by digest -------------------------------------------------
log "pulling $REF"
pull_out=$(d pull "$REF") || die "pull failed (private repository? see 'Registry login' in deploy/README.md)"
printf '%s\n' "$pull_out"
digest=$(printf '%s\n' "$pull_out" | sed -n 's/^Digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' | tail -n 1)
[ -n "$digest" ] || die "could not read the pulled digest"
PINNED=$REPO@$digest
# Docker lists Docker Hub digests without the docker.io/ prefix.
d image inspect --format '{{ range .RepoDigests }}{{ println . }}{{ end }}' "$REF" |
  grep -qxF -e "$PINNED" -e "$NAME@$digest" || die "$PINNED is not a repo digest of $REF"

# --- 2. revision and platform ------------------------------------------------
rev=$(label "$PINNED" org.opencontainers.image.revision)
[ "$rev" = "$SHA" ] || die "revision label is '$rev', expected $SHA"
plat=$(d image inspect --format '{{ .Os }}/{{ .Architecture }}' "$PINNED")
[ "$plat" = "$PLATFORM" ] || die "image platform is $plat, expected $PLATFORM"
NEW_ID=$(d image inspect --format '{{ .Id }}' "$PINNED")
log "verified $PINNED (revision $rev, $plat)"

# --- 3. provenance -------------------------------------------------------------
if [ "$VERIFY" = 1 ] || { [ "$VERIFY" = auto ] && command -v gh >/dev/null 2>&1; }; then
  log "verifying build provenance with gh"
  gh attestation verify "oci://$PINNED" --repo "$ATTEST_REPO" ||
    die "attestation verification failed (needs 'gh auth login'; a private repository also needs 'docker login' as this user). KEYMESH_VERIFY_ATTESTATION=0 skips it."
else
  log "gh not installed or KEYMESH_VERIFY_ATTESTATION=0: provenance NOT verified"
fi

# --- 4. bundle hashes ------------------------------------------------------------
tmp=$(mktemp -d)
bundle_cid=
cleanup() {
  if [ -n "$bundle_cid" ]; then d rm -f "$bundle_cid" >/dev/null 2>&1 || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
bundle_cid=$(d create "$PINNED")
d cp "$bundle_cid:/app/dist/web/browser" - | tar -x -C "$tmp"
d rm "$bundle_cid" >/dev/null
bundle_cid=
[ -f "$tmp/browser/index.html" ] || die "image holds no bundle at /app/dist/web/browser"
log "bundle: $(find "$tmp/browser" -type f | wc -l | tr -d ' ') files; key file sha256:"
(cd "$tmp/browser" && sha256 wasm/keymesh_wasm_bg.wasm main-*.js ngsw.json)
if [ -n "${KEYMESH_LEDGER:-}" ]; then
  node "$HERE/../scripts/asset-ledger.mjs" "$tmp/browser" --out "$tmp/ledger.json"
  node "$HERE/../scripts/asset-ledger.mjs" --compare "$KEYMESH_LEDGER" "$tmp/ledger.json" ||
    die "bundle does not match $KEYMESH_LEDGER"
fi

# --- 5. current web and rollback tag ----------------------------------------
old_cid=$(web_container)
ROLLBACK=
if [ -n "$old_cid" ]; then
  old_id=$(d inspect --format '{{ .Image }}' "$old_cid")
  if [ "$old_id" = "$NEW_ID" ] && wait_healthy "$old_cid"; then
    log "web already runs $PINNED and is healthy; nothing to do"
    exit 0
  fi
  old_rev=$(label "$old_id" org.opencontainers.image.revision | tr -d '\r\n' | tr -c 'A-Za-z0-9_.-' '_' | cut -c 1-64)
  case $old_rev in '' | unknown | '_no_value_') old_rev=unknown-$(printf '%s' "$old_id" | sed 's/^sha256://' | cut -c 1-12) ;; esac
  ROLLBACK=keymesh-web:rollback-$old_rev
  d tag "$old_id" "$ROLLBACK"
  log "current web image tagged $ROLLBACK"
else
  log "no existing web container; nothing to roll back to"
fi

# --- 6 and 7. swap web, wait, roll back on failure ------------------------------
log "recreating web from $PINNED"
if recreate_web "$PINNED"; then
  [ "$(d inspect --format '{{ .Image }}' "$(web_container)")" = "$NEW_ID" ] ||
    die "web is healthy but not running $PINNED"
  log "deployed $PINNED (revision $SHA); web is healthy"
  log "for later manual compose commands use: KEYMESH_WEB_IMAGE=$PINNED"
  exit 0
fi

failed=$(web_container)
if [ -n "$failed" ]; then d logs --tail 30 "$failed" >&2 || true; fi
[ -n "$ROLLBACK" ] || die "new web is not healthy and there is no previous image to roll back to"
log "rolling back web to $ROLLBACK"
if recreate_web "$ROLLBACK"; then
  die "deploy of $SHA failed; rolled back to $ROLLBACK (healthy). Use KEYMESH_WEB_IMAGE=$ROLLBACK for manual compose commands."
fi
die "deploy of $SHA failed AND rollback to $ROLLBACK is not healthy; check 'sudo docker compose -p keymesh ps'"
