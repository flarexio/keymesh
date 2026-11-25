#!/bin/sh
# CI helper for the `manifest` job (.github/workflows/ci.yml): joins the
# per-platform keymesh-web digests of a release into one tagged index, then
# checks it.
#
# Inputs (environment): IMAGE (e.g. docker.io/<ns>/keymesh-web), AMD64 and ARM64
# (the per-platform manifest digests the image legs pushed), VERSION (e.g. 0.6.0;
# GITHUB_REF must be refs/tags/v$VERSION), LATEST (true to also move :latest),
# GITHUB_SHA, GITHUB_REF, GITHUB_OUTPUT. Needs docker buildx, jq and sha256sum
# or shasum. Tags: <version>, sha-<sha> and, when LATEST=true, latest.
# Writes `digest` (the index digest) and `tags` to GITHUB_OUTPUT.
set -eu

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum; else shasum -a 256; fi; }
hex64='sha256:[0-9a-f]\{64\}'
for v in "$AMD64" "$ARM64"; do
  expr "$v" : "^$hex64\$" >/dev/null || fail "not a digest: $v"
done
printf '%s' "$GITHUB_SHA" | grep -Eqx '[0-9a-f]{40}' || fail "GITHUB_SHA is not a full commit sha"

printf '%s' "$VERSION" | grep -Eqx '(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)' || fail "VERSION is not MAJOR.MINOR.PATCH: '$VERSION'"
[ "$GITHUB_REF" = "refs/tags/v$VERSION" ] || fail "GITHUB_REF $GITHUB_REF is not refs/tags/v$VERSION"
case $LATEST in true | false) ;; *) fail "LATEST must be true or false: '$LATEST'" ;; esac

tags="$IMAGE:$VERSION
$IMAGE:sha-$GITHUB_SHA"
if [ "$LATEST" = true ]; then
  tags="$tags
$IMAGE:latest"
fi

raw=$(mktemp)
trap 'rm -f "$raw"' EXIT
# check_index <index json file>: exactly linux/amd64 and linux/arm64, each the
# digest its leg pushed, and the revision annotation.
check_index() {
  got=$(jq -r '.manifests[] | "\(.platform.os)/\(.platform.architecture)\(if .platform.variant then "/" + .platform.variant else "" end) \(.digest)"' "$1" | sort)
  want=$(printf 'linux/amd64 %s\nlinux/arm64 %s' "$AMD64" "$ARM64")
  [ "$got" = "$want" ] || fail "index manifests are:
$got
expected:
$want"
  rev=$(jq -r '.annotations["org.opencontainers.image.revision"] // ""' "$1")
  [ "$rev" = "$GITHUB_SHA" ] || fail "index revision annotation is '$rev'"
}

set -- --annotation "index:org.opencontainers.image.revision=$GITHUB_SHA"
# Check the index before any tag is pushed, then push it and check what the
# registry serves.
docker buildx imagetools create --dry-run "$@" "$IMAGE@$AMD64" "$IMAGE@$ARM64" >"$raw"
check_index "$raw"
for t in $tags; do set -- "$@" --tag "$t"; done
docker buildx imagetools create "$@" "$IMAGE@$AMD64" "$IMAGE@$ARM64"

# Index digest = sha256 of the raw index the registry serves for the sha tag.
docker buildx imagetools inspect --raw "$IMAGE:sha-$GITHUB_SHA" >"$raw"
digest=sha256:$(sha256 <"$raw" | cut -d ' ' -f 1)
shown=$(docker buildx imagetools inspect "$IMAGE:sha-$GITHUB_SHA" | sed -n 's/^Digest: *//p' | head -n 1)
[ "$shown" = "$digest" ] || fail "index digest mismatch: computed $digest, registry shows $shown"
check_index "$raw"

# Every tag resolves to this index.
for t in $tags; do
  d=$(docker buildx imagetools inspect "$t" | sed -n 's/^Digest: *//p' | head -n 1)
  [ "$d" = "$digest" ] || fail "$t resolves to $d, not $digest"
done

echo "index $IMAGE@$digest"
printf '%s\n' "$got"
{
  echo "digest=$digest"
  echo "tags<<EOF"
  printf '%s\n' "$tags"
  echo "EOF"
} >>"$GITHUB_OUTPUT"
