#!/bin/sh
# Deploy a CI-built keymesh-web image on the Pi (see deploy/README.md).
#
#   KEYMESH_IMAGE_REPO=<namespace>/keymesh-web \
#     deploy/pull-deploy.sh <release version | full 40-hex commit sha> [<namespace>/keymesh-web]
#
# Images are published only by release tags (vMAJOR.MINOR.PATCH), so the first
# argument is a release version (0.6.0 or v0.6.0) or the full commit sha of one.
#
# 1. Pulls docker.io/<repo>:<version> or :sha-<sha> (a linux/amd64 + linux/arm64
#    index) for this host's platform and pins it by the INDEX digest. A version is
#    resolved to its tag's commit with `git ls-remote` on the GitHub repository.
# 2. Refuses unless the revision label is that commit and the pulled image's
#    platform is this host's (the Docker daemon's os/arch, or KEYMESH_PLATFORM).
# 3. Verifies the index's build provenance with `gh attestation verify` when gh is
#    installed: signed by ci.yml of flarexio/keymesh running for a refs/tags/v*
#    release tag (that exact tag when a version is given), built from the commit,
#    on a GitHub-hosted runner.
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
#   KEYMESH_PLATFORM            expected os/arch (default: the Docker daemon's, e.g. linux/arm64)
#   KEYMESH_HEALTH_TIMEOUT      seconds to wait for healthy (default 150)
#   SUDO                        command prefix for docker (default "sudo"; empty if root)
#   KEYMESH_IMAGE_REGISTRY      registry host (default docker.io; override only for local testing)
#   KEYMESH_GIT_REMOTE          git URL the release tags are read from (default
#                               https://github.com/flarexio/keymesh; override only for local testing)
set -eu

REGISTRY=${KEYMESH_IMAGE_REGISTRY:-docker.io}
ATTEST_REPO=flarexio/keymesh
GIT_REMOTE=${KEYMESH_GIT_REMOTE:-https://github.com/$ATTEST_REPO}
# The signer: ci.yml of this repository running for a release tag.
SIGNER_RE='^https://github\.com/flarexio/keymesh/\.github/workflows/ci\.yml@refs/tags/v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
PLATFORM=${KEYMESH_PLATFORM:-}
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
  $SUDO env KEYMESH_WEB_IMAGE="$img" DOCKER_DEFAULT_PLATFORM="$PLATFORM" \
    docker compose -f "$COMPOSE_FILE" "$@"
}
label() { d image inspect --format "{{ index .Config.Labels \"$2\" }}" "$1"; }
# pinspect <format> <ref>: inspect the $PLATFORM image of an index. The containerd
# image store needs --platform (Docker >= 28); older Docker has no such flag and
# stores only the pulled platform, so fall back to a plain inspect there.
pinspect() {
  d image inspect --platform "$PLATFORM" --format "$1" "$2" 2>/dev/null ||
    d image inspect --format "$1" "$2"
}
web_container() {
  d ps -aq --filter label=com.docker.compose.project=keymesh \
    --filter label=com.docker.compose.service=web | head -n 1
}
# container_platform <container>: os/arch the container runs (empty on Docker
# without ImageManifestDescriptor, where image IDs are per platform anyway).
container_platform() {
  d inspect --format '{{ with .ImageManifestDescriptor }}{{ with .Platform }}{{ .OS }}/{{ .Architecture }}{{ end }}{{ end }}' "$1" 2>/dev/null || true
}
# runs_new <container>: the container runs the pinned image for $PLATFORM.
runs_new() {
  [ "$(d inspect --format '{{ .Image }}' "$1")" = "$NEW_ID" ] || return 1
  cp=$(container_platform "$1")
  [ -z "$cp" ] || [ "$cp" = "$PLATFORM" ]
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
[ $# -eq 1 ] || [ $# -eq 2 ] || die "usage: $0 <release version (0.6.0) | full 40-hex commit sha> [<namespace>/<name>]"
NAME=${2:-${KEYMESH_IMAGE_REPO:-}}
printf '%s' "$NAME" | grep -Eqx '[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*' ||
  die "set KEYMESH_IMAGE_REPO (or pass it as the 2nd argument) to <namespace>/<name>: '$NAME'"
REPO=$REGISTRY/$NAME
case $VERIFY in auto | 0 | 1) ;; *) die "KEYMESH_VERIFY_ATTESTATION must be auto, 0 or 1" ;; esac
VERSION=
if printf '%s' "$1" | grep -Eqx 'v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'; then
  VERSION=${1#v}
  TAG=v$VERSION
  # The commit the release tag points to (peeled, for an annotated tag).
  refs=$(git ls-remote "$GIT_REMOTE" "refs/tags/$TAG" "refs/tags/$TAG^{}") ||
    die "could not read release tags from $GIT_REMOTE"
  SHA=$(printf '%s\n' "$refs" | awk -v p="refs/tags/$TAG^{}" '$2 == p { print $1 }')
  [ -n "$SHA" ] || SHA=$(printf '%s\n' "$refs" | awk -v t="refs/tags/$TAG" '$2 == t { print $1 }')
  [ -n "$SHA" ] || die "release tag $TAG does not exist in $GIT_REMOTE"
  REF=$REPO:$VERSION
  log "release $TAG is commit $SHA"
else
  SHA=$1
  case $SHA in *[!0-9a-f]* | '') die "expected a release version (0.6.0) or a lowercase hex commit sha: $SHA" ;; esac
  REF=$REPO:sha-$SHA
fi
printf '%s' "$SHA" | grep -Eqx '[0-9a-f]{40}' || die "commit sha must be the full 40 lowercase hex characters: $SHA"
[ -n "$PLATFORM" ] || PLATFORM=$(d version --format '{{ .Server.Os }}/{{ .Server.Arch }}')
case $PLATFORM in linux/amd64 | linux/arm64) ;; *) die "unsupported platform '$PLATFORM' (the image has linux/amd64 and linux/arm64)" ;; esac

# --- 1. pull and pin by digest -------------------------------------------------
log "pulling $REF for $PLATFORM"
pull_out=$(d pull --platform "$PLATFORM" "$REF") || die "pull failed (private repository? see 'Registry login' in deploy/README.md)"
printf '%s\n' "$pull_out"
digest=$(printf '%s\n' "$pull_out" | sed -n 's/^Digest: \(sha256:[0-9a-f]\{64\}\)$/\1/p' | tail -n 1)
[ -n "$digest" ] || die "could not read the pulled digest"
PINNED=$REPO@$digest
# Docker lists Docker Hub digests without the docker.io/ prefix.
d image inspect --format '{{ range .RepoDigests }}{{ println . }}{{ end }}' "$REF" |
  grep -qxF -e "$PINNED" -e "$NAME@$digest" || die "$PINNED is not a repo digest of $REF"

# --- 2. revision and platform ------------------------------------------------
rev=$(pinspect '{{ index .Config.Labels "org.opencontainers.image.revision" }}' "$PINNED")
[ "$rev" = "$SHA" ] || die "revision label is '$rev', expected $SHA"
plat=$(pinspect '{{ .Os }}/{{ .Architecture }}' "$PINNED")
[ "$plat" = "$PLATFORM" ] || die "image platform is $plat, expected $PLATFORM"
NEW_ID=$(d image inspect --format '{{ .Id }}' "$PINNED")
log "verified $PINNED (revision $rev, $plat)"

# --- 3. provenance -------------------------------------------------------------
if [ "$VERIFY" = 1 ] || { [ "$VERIFY" = auto ] && command -v gh >/dev/null 2>&1; }; then
  log "verifying build provenance with gh"
  # Signed by ci.yml for a v* release tag (exactly $TAG for a version), built
  # from $SHA on a GitHub-hosted runner.
  set -- --repo "$ATTEST_REPO" --cert-identity-regex "$SIGNER_RE" --source-digest "$SHA" --deny-self-hosted-runners
  if [ -n "$VERSION" ]; then set -- "$@" --source-ref "refs/tags/$TAG"; fi
  gh attestation verify "oci://$PINNED" "$@" ||
    die "attestation verification failed (needs 'gh auth login'; a private repository also needs 'docker login' as this user). KEYMESH_VERIFY_ATTESTATION=0 skips it."
else
  log "gh not installed or KEYMESH_VERIFY_ATTESTATION=0: provenance NOT verified"
fi

# --- 4. bundle hashes ------------------------------------------------------------
tmp=$(mktemp -d)
bundle_cid=
# shellcheck disable=SC2317,SC2329 # invoked indirectly by `trap cleanup EXIT` below (0.9 reports SC2317, 0.10+ SC2329)
cleanup() {
  if [ -n "$bundle_cid" ]; then d rm -f "$bundle_cid" >/dev/null 2>&1 || true; fi
  rm -rf "$tmp"
}
trap cleanup EXIT
trap 'exit 130' INT TERM
bundle_cid=$(d create --platform "$PLATFORM" "$PINNED")
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
  if runs_new "$old_cid" && wait_healthy "$old_cid"; then
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
  runs_new "$(web_container)" || die "web is healthy but not running $PINNED for $PLATFORM"
  log "deployed $PINNED (${VERSION:+release $VERSION, }revision $SHA); web is healthy"
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
