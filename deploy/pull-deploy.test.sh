#!/bin/sh
# Tests for the provenance policy of deploy/pull-deploy.sh (review M-1):
# verification is mandatory; a missing gh or a failed verification refuses
# before anything is deployed; only an explicit KEYMESH_VERIFY_ATTESTATION=0
# skips it, with a loud warning. Runs the real script against fake docker and
# gh on a sandboxed PATH (no network, no registry, no real gh). Synthetic only.
#
#   sh deploy/pull-deploy.test.sh
# check() evaluates its condition later (after run() set rc), so the single
# quotes and the "unused" rc are intended.
# shellcheck disable=SC2016,SC2034
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
SCRIPT=$HERE/pull-deploy.sh
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
SHA=0123456789abcdef0123456789abcdef01234567
DIGEST=sha256:$(printf 'a%.0s' $(seq 1 64))
fails=0

# A PATH with only the tools the script needs (so a gh elsewhere on the host is not found).
base=$work/base
mkdir -p "$base"
for t in sh sed grep awk cat head tail tr cut mktemp rm tar find wc dirname env sleep seq; do
  p=$(command -v "$t") || { echo "missing tool $t" >&2; exit 2; }
  ln -s "$p" "$base/$t"
done

fake=$work/fake
mkdir -p "$fake"
cat >"$fake/docker" <<EOF
#!/bin/sh
echo "docker \$*" >>"$work/docker.log"
case "\$*" in
  'pull --platform linux/arm64 '*) echo "Digest: $DIGEST" ;;
  *'.RepoDigests'*) echo "example/keymesh-web@$DIGEST" ;;
  *'org.opencontainers.image.revision'*) echo "$SHA" ;;
  *'.Os }}/{{ .Architecture'*) echo linux/arm64 ;;
  *'{{ .Id }}'*) echo sha256:feedface ;;
  *) echo "fake docker: not emulated: \$*" >&2; exit 1 ;;
esac
EOF
cat >"$fake/gh" <<EOF
#!/bin/sh
echo "gh \$*" >>"$work/gh.log"
exit "\${FAKE_GH_RC:-0}"
EOF
chmod +x "$fake/docker" "$fake/gh"
mkdir -p "$work/nogh"
cp "$fake/docker" "$work/nogh/docker"

# run <name> <path-dirs> [VAR=value ...]: runs the script, records rc/out/err.
run() {
  name=$1
  dirs=$2
  shift 2
  : >"$work/docker.log"
  : >"$work/gh.log"
  set +e
  env -i PATH="$dirs:$base" HOME="$work" SUDO= KEYMESH_PLATFORM=linux/arm64 "$@" \
    sh "$SCRIPT" "$SHA" example/keymesh-web >"$work/$name.out" 2>"$work/$name.err"
  rc=$?
  set -e
}
check() {
  if eval "$2"; then
    echo "ok   $1"
  else
    echo "FAIL $1"
    sed 's/^/     | /' "$work/$name.err" | head -n 12
    fails=$((fails + 1))
  fi
}
has() { grep -q -- "$2" "$work/$1"; }

run default-no-gh "$work/nogh"
check "default without gh: refused" '[ $rc -ne 0 ]'
check "default without gh: says why (gh is required)" 'has default-no-gh.err "gh"'
check "default without gh: refused before any pull" '! has docker.log "pull"'

run auto "$fake" KEYMESH_VERIFY_ATTESTATION=auto
check "auto is no longer a mode: refused" '[ $rc -ne 0 ] && has auto.err "KEYMESH_VERIFY_ATTESTATION"'
check "auto: refused before any pull" '! has docker.log "pull"'

run bogus "$fake" KEYMESH_VERIFY_ATTESTATION=yes
check "unknown value: refused" '[ $rc -ne 0 ] && ! has docker.log "pull"'

run explicit-1-no-gh "$work/nogh" KEYMESH_VERIFY_ATTESTATION=1
check "=1 without gh: refused before any pull" '[ $rc -ne 0 ] && ! has docker.log "pull"'

run gh-fails "$fake" FAKE_GH_RC=1
check "verification fails: refused" '[ $rc -ne 0 ] && has gh-fails.err "attestation verification failed"'
check "verification fails: nothing created or deployed" '! has docker.log "create" && ! has docker.log "compose"'

run gh-ok "$fake"
check "verification runs by default with the tag signer and source commit" \
  'has gh.log "attestation verify oci://docker.io/example/keymesh-web@$DIGEST" && has gh.log "--cert-identity-regex" && has gh.log "--source-digest $SHA" && has gh.log "--deny-self-hosted-runners"'
check "verified: continues to the bundle step" 'has gh-ok.out "verifying build provenance" && has docker.log "create"'
check "verified: no skip warning" '! has gh-ok.err "WARNING"'

run skip "$work/nogh" KEYMESH_VERIFY_ATTESTATION=0
check "=0: skipping is loud (warning on stderr)" 'has skip.err "WARNING" && has skip.err "NOT verified"'
check "=0: gh is not run" '[ ! -s "$work/gh.log" ]'

if [ "$fails" -ne 0 ]; then
  echo "$fails pull-deploy policy check(s) failed" >&2
  exit 1
fi
echo "all pull-deploy policy checks passed"
