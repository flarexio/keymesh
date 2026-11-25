#!/bin/sh
# CI helper for the `changes` job (.github/workflows/ci.yml): decides whether a
# run must build and test (build=true) or only touches documentation
# (build=false: every changed path is **/*.md, docs/** or LICENSE).
#
# Fails closed: tags, workflow_dispatch, unknown events, a missing or
# unreachable base, or an empty diff all build.
#   pull_request  the merge commit against its first parent (the base tip)
#   push          github.event.before..GITHUB_SHA on branches
# Inputs (environment): GITHUB_EVENT_NAME, GITHUB_REF, GITHUB_SHA, BEFORE,
# GITHUB_OUTPUT. Needs the history (checkout fetch-depth: 0).
set -eu

decide() {
  echo "build=$1" >>"$GITHUB_OUTPUT"
  echo "build=$1: $2"
  if [ "$1" = false ]; then echo "::notice title=docs-only change::$2"; fi
  exit 0
}

case $GITHUB_EVENT_NAME in
  pull_request)
    git rev-parse --verify -q "HEAD^2^{commit}" >/dev/null || decide true "HEAD is not a pull request merge commit"
    base=HEAD^1
    head=HEAD
    ;;
  push)
    case $GITHUB_REF in refs/heads/*) ;; *) decide true "push of $GITHUB_REF always builds" ;; esac
    case ${BEFORE:-} in '' | *[!0]*) ;; *) decide true "new branch: no previous commit to compare" ;; esac
    [ -n "${BEFORE:-}" ] || decide true "no previous commit to compare"
    git rev-parse --verify -q "$BEFORE^{commit}" >/dev/null || decide true "previous commit $BEFORE is not in the history (force push?)"
    base=$BEFORE
    head=$GITHUB_SHA
    ;;
  *) decide true "$GITHUB_EVENT_NAME always builds" ;;
esac

files=$(git diff --name-only "$base" "$head")
[ -n "$files" ] || decide true "no changed files between $base and $head"
n=$(printf '%s\n' "$files" | wc -l | tr -d ' ')
code=$(printf '%s\n' "$files" | while IFS= read -r f; do
  case $f in (*.md | docs/* | LICENSE) ;; (*) printf '%s\n' "$f" ;; esac
done)
if [ -n "$code" ]; then
  decide true "$n changed files, not docs-only (first: $(printf '%s\n' "$code" | head -n 1))"
fi
decide false "all $n changed files are documentation (**/*.md, docs/**, LICENSE); build, test and image steps are skipped"
