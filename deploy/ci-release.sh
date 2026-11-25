#!/bin/sh
# CI helper for releases (.github/workflows/ci.yml). Two subcommands:
#
#   ci-release.sh meta
#     Decides whether this run publishes the keymesh-web image. Only a strict
#     vMAJOR.MINOR.PATCH tag in flarexio/keymesh publishes, pushed or re-run with
#     workflow_dispatch on that tag; every other run (branches, main, pull
#     requests, forks) builds without pushing. Inputs (environment):
#     GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_REPOSITORY, DOCKERHUB_REPOSITORY,
#     HAS_CREDENTIALS, GITHUB_OUTPUT. Writes publish, reason and version (no "v")
#     to GITHUB_OUTPUT. A v* tag that is not vMAJOR.MINOR.PATCH is an error.
#
#   ci-release.sh latest <version>
#     Reads `git ls-remote --tags` lines (or bare tag names) on stdin and prints
#     true when <version> is the highest vMAJOR.MINOR.PATCH release, else false,
#     so re-publishing an older release never moves :latest backwards.
set -eu

fail() { printf '::error::%s\n' "$*" >&2; exit 1; }
semver='(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)'

case ${1:-} in
meta)
  publish=false
  reason=
  version=
  case $GITHUB_REF in
    refs/tags/v*)
      tag=${GITHUB_REF#refs/tags/}
      printf '%s' "$tag" | grep -Eqx "v$semver" || fail "tag $tag is not vMAJOR.MINOR.PATCH (e.g. v0.6.0); nothing is published"
      version=${tag#v}
      ;;
  esac
  if [ "$GITHUB_REPOSITORY" != flarexio/keymesh ]; then
    reason="build only: $GITHUB_REPOSITORY is not flarexio/keymesh"
  elif [ -z "$version" ]; then
    reason="build only: $GITHUB_EVENT_NAME on $GITHUB_REF does not publish (releases publish from v* tags)"
  elif [ "$GITHUB_EVENT_NAME" != push ] && [ "$GITHUB_EVENT_NAME" != workflow_dispatch ]; then
    reason="build only: $GITHUB_EVENT_NAME does not publish"
  elif ! printf '%s' "${DOCKERHUB_REPOSITORY:-}" | grep -Eqx '[a-z0-9]+([._-][a-z0-9]+)*/[a-z0-9]+([._-][a-z0-9]+)*'; then
    reason="build only: repository variable DOCKERHUB_REPOSITORY is missing or not <namespace>/<name>"
  elif [ "${HAS_CREDENTIALS:-}" != true ]; then
    reason="build only: secrets REGISTRY_USERNAME and REGISTRY_PASSWORD are not both set"
  else
    publish=true
  fi
  {
    echo "publish=$publish"
    echo "reason=$reason"
    echo "version=$version"
  } >>"$GITHUB_OUTPUT"
  echo "publish=$publish version=$version${reason:+ ($reason)}"
  ;;
latest)
  v=${2:-}
  printf '%s' "$v" | grep -Eqx "$semver" || fail "not a MAJOR.MINOR.PATCH version: '$v'"
  highest=$({ sed 's#.*refs/tags/##; s#^\(v[^^]*\)^{}$#\1#'; echo "v$v"; } | grep -Ex "v$semver" | sed 's/^v//' |
    sort -t . -k 1,1n -k 2,2n -k 3,3n | tail -n 1)
  if [ "$highest" = "$v" ]; then echo true; else echo false; fi
  ;;
*)
  fail "usage: $0 meta | latest <version>"
  ;;
esac
