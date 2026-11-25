# Private HTTPS deployment (Docker)

**Experimental, synthetic data only.**

- **Scope:** the Keymesh web app, served as `https://keymesh.cloud/` to devices on the VPN.
- **Not covered:** this is not a production deployment and not a trusted-client (gate C) acceptance; see `docs/DELIVERY.md`.

**Keymesh ships only the web container.** TLS, certificates and routing belong to the host's shared reverse proxy (a Traefik that serves several sites), which is **not part of this repository**.

| Service | Image | Binds | Role |
|---|---|---|---|
| `web` | `$KEYMESH_WEB_IMAGE` (a CI-built multi-arch Docker Hub image pinned by index digest, see below), else `keymesh-web:local` built from `deploy/web.Dockerfile` | `127.0.0.1:4320` (HTTP, loopback only) | `apps/web/scripts/serve.mjs` serving the already-built `apps/web/dist/web/browser` |

## Design rules
- **Host networking:** Docker publishes no ports and adds no NAT or iptables rules. `web` binds `127.0.0.1:4320` only, so nothing off the host reaches it except through the host proxy.
- **Hardening:** read-only root filesystem, `no-new-privileges`, `cap_drop: ALL`, uid 1000 and `restart: unless-stopped`. It mounts no Docker socket, home or repo. The health check is the image's `HEALTHCHECK` (`deploy/web.Dockerfile`).
- **What the image holds:** only `serve.mjs`, `favicon.mjs` and the built bundle, enforced by the allowlist in `web.Dockerfile.dockerignore`.
- **Unchanged security behaviour:** `serve.mjs` sets CSP, COOP, nosniff and no-referrer and keeps its SPA containment. The website-icon route stays off: `KEYMESH_FAVICON` is not set.

## Route the host proxy needs
- **Host:** `keymesh.cloud` only, **HTTPS only**, TLS ≥ 1.2 with **strict SNI**.
- **Redirect:** HTTP→HTTPS for `keymesh.cloud`.
- **HSTS:** `max-age=31536000`.
- **Backend:** `http://127.0.0.1:4320`.
- **Certificate:** issued by the FlareX CA (step-ca at `ca.cloud`) and managed by the host proxy.

A minimal Traefik file-provider sketch, for reference only. The entry points (`web` :80, `websecure` :443) and the certificate resolver (`stepca` here) are the host proxy's own:

```yaml
http:
  routers:
    keymesh:
      rule: Host(`keymesh.cloud`)
      entryPoints: [websecure]
      service: keymesh
      middlewares: [keymesh-hsts]
      tls: { certResolver: stepca }
    keymesh-http:
      rule: Host(`keymesh.cloud`)
      entryPoints: [web]
      service: keymesh
      middlewares: [keymesh-to-https]
  middlewares:
    keymesh-to-https: { redirectScheme: { scheme: https } }
    keymesh-hsts: { headers: { stsSeconds: 31536000 } }
  services:
    keymesh:
      loadBalancer: { servers: [{ url: "http://127.0.0.1:4320" }] }
tls:
  options:
    default: { minVersion: VersionTLS12, sniStrict: true }
```

## CI-built image (Docker Hub)

The preferred way to update `web`: a **release tag** (`vMAJOR.MINOR.PATCH`, e.g. `v0.6.0`) makes GitHub Actions publish a **multi-arch** image (`linux/amd64` and `linux/arm64`) built from the bundle that passed E2E in that same run, and the host pulls it by version (or commit) and pins it by digest. The Pi (arm64) and an amd64 host such as the cloud GCE VM pull the **same tag**; Docker selects the matching platform.

**What runs when.**

| Event | rust, web, lint | image legs | Docker Hub push, `manifest`, attestation |
|---|---|---|---|
| Push of a `vMAJOR.MINOR.PATCH` tag | run | build and push by digest | **yes** |
| `workflow_dispatch` on such a tag (re-publish) | run | build and push by digest | **yes** |
| Push to `main` or `feature/**`, pull request, `workflow_dispatch` on a branch | run | build only | no |
| Any of the above except tags/dispatch, docs-only change | skipped | run, every step skipped | no |

- **Docs-only:** job `changes` (`scripts/ci-changes.sh`) sets `build=false` only when every changed path is `**/*.md`, `docs/**` or `LICENSE` (pull request: the merge commit against the base; push: `before..after`). Anything else, a new branch, a force push, a tag or `workflow_dispatch` builds. The required checks still report: skipped `rust`/`web`/`lint` pass, and the `image` matrix still runs so `image (linux/amd64)` and `image (linux/arm64)` succeed.
- **A `v*` tag that is not `vMAJOR.MINOR.PATCH`** (e.g. `v1.0.0-rc.1`) fails the image legs and publishes nothing.
- **Concurrency:** a newer push to a pull request cancels its older run. Tag, `main`, branch and dispatch runs are never cancelled.
- **Caches:** `Swatinem/rust-cache` in `rust` and in `web`'s WASM build, saved only by pushes to branches. On a tag, `web` (which builds the released bundle) restores no Rust or npm cache, and the image and `manifest` jobs never use caches.

**Release flow.**
0. **Lint.** Job `lint` runs shellcheck on every tracked `*.sh` and actionlint (pinned, checksum-verified, with shellcheck) on the workflows. Any finding fails it, and nothing is built or published without it.
1. **Build.** `ci.yml` job `web` builds the WASM and Angular bundle, runs unit tests and E2E, then uploads that exact `dist/web/browser` (artifact `web-dist`) with its asset ledger.
2. **Image (matrix).** Job `image` (needs `rust`, `web` and `lint`) has one leg per platform, each on its own **native** runner: `linux/amd64` on `ubuntu-24.04` and `linux/arm64` on `ubuntu-24.04-arm` (COPY-only Dockerfile, no QEMU). Each leg downloads the artifact, checks it file by file against the tested ledger, and builds `deploy/web.Dockerfile` for its platform with labels `org.opencontainers.image.revision` (full commit SHA), `source` and `created`. When publishing, it pushes its manifest **by digest only** (no tag) and uploads the digest as artifact `digests-<arch>`.
3. **Index (`manifest` job).** Only when the legs published, and only after `rust`, `web` and `lint` passed in the same run: checks both legs used the identical bundle, then `docker buildx imagetools create` joins the two digests into one index with the annotation `org.opencontainers.image.revision=<sha>`. It checks the index **before** pushing any tag (`--dry-run`: exactly `linux/amd64` and `linux/arm64`, each the digest its leg pushed), then tags it `<version>` (e.g. `0.6.0`, no `v`), `sha-<full sha>` and `latest`, re-checks what the registry serves, and attests build provenance for the **index digest** with `actions/attest-build-provenance` (pushed to the registry and stored on GitHub; signed by `ci.yml@refs/tags/v<version>`).
   - **`latest`** moves only when the version is the highest `vMAJOR.MINOR.PATCH` tag in the repository, so re-publishing an older release never moves it back.
   - **Push rules:** only for a `vMAJOR.MINOR.PATCH` tag in `flarexio/keymesh` (`deploy/ci-release.sh meta`), and only when the Docker Hub settings below exist. `main`, branches and pull requests, including forks, build both platforms without logging in or pushing, and `manifest` is skipped; missing settings only skip the push with a notice.
   - **`:main`** is no longer pushed. The existing `:main` and older `sha-<sha>` tags from main stay on Docker Hub; their attestations are signed by `refs/heads/main`, which `pull-deploy.sh` no longer accepts (see Roll back).
   - **Permissions:** only `manifest` has `id-token: write`, `attestations: write` and `artifact-metadata: write`; the legs have `contents: read`.
4. **Record.** The `manifest` summary shows the index digest, both platform digests, the tags and the sha256 of `wasm/keymesh_wasm_bg.wasm`, `main-*.js` and `ngsw.json` (one bundle, identical in both platforms). Artifact `asset-ledger` (`asset-ledger.json`) records the same plus every bundle file with sha256 and size. Each leg's summary shows its own digest or why it did not push.

**Index digest vs platform digests.** `sha-<sha>` names an **index** (manifest list). Its digest is what CI attests, what `pull-deploy.sh` pins and what acceptance refers to. Each platform image inside it has its own **platform digest** (listed in the summary and the ledger); a host pulls the one for its own platform through the index, so an amd64 host and the Pi report the same index digest but run different platform images. The bundle files inside both are byte-identical.
5. **Deploy.** On the host, `deploy/pull-deploy.sh <version>` (below).

**Cut a release (FlareX).** Tag a commit on `main` that passed CI and push the tag: `git tag -a v0.6.0 -m v0.6.0 <sha> && git push origin v0.6.0`. Re-publish the same release with *Run workflow* on the tag (`workflow_dispatch`).

**One-time setup (FlareX; Claude never creates or handles tokens).**
1. **Credentials:** CI logs in with the flarexio **organization** secrets `REGISTRY_USERNAME` and `REGISTRY_PASSWORD`, which are already shared with this repository. The account needs push access to the namespace.
2. **Repository:** set the Actions variable `DOCKERHUB_REPOSITORY` = `<namespace>/keymesh-web`. Docker Hub creates the repository on the first push, using the account's default privacy.
3. **Visibility:** after the first push, check the repository's visibility on Docker Hub (see Registry login below).

**Registry login on the host.** A public Docker Hub repository needs no login. A private one needs a one-time `sudo docker login` by FlareX, with a token that can read the repository (Read-only scope is enough). Don't put tokens in this repository, shell history or scripts.

**Deploy a release** (from the repository root; Docker needs sudo on the host):

```sh
KEYMESH_IMAGE_REPO=<namespace>/keymesh-web deploy/pull-deploy.sh 0.6.0      # or v0.6.0
KEYMESH_IMAGE_REPO=<namespace>/keymesh-web deploy/pull-deploy.sh <full 40-hex sha of a release>
```

The script, using `sudo docker`:
1. With a version, reads the commit of tag `v<version>` (peeled) with `git ls-remote https://github.com/flarexio/keymesh`, then pulls `docker.io/<repo>:<version>`; with a SHA, pulls `docker.io/<repo>:sha-<sha>`. Either way it pulls for this host's platform and pins the image by the **index** digest.
2. **Refuses** unless the revision label is exactly that commit and the pulled image's os/arch is this host's: the Docker daemon's `{{.Server.Os}}/{{.Server.Arch}}` (arm64 on the Pi, amd64 on an amd64 host), or `KEYMESH_PLATFORM` if set (`linux/amd64` or `linux/arm64` only).
3. Runs `gh attestation verify oci://docker.io/<repo>@sha256:<index digest> --repo flarexio/keymesh` when `gh` is installed, requiring the signer `https://github.com/flarexio/keymesh/.github/workflows/ci.yml@refs/tags/vMAJOR.MINOR.PATCH` (`--cert-identity-regex`), the source commit (`--source-digest <sha>`), a GitHub-hosted runner, and with a version exactly `--source-ref refs/tags/v<version>`. Set `KEYMESH_VERIFY_ATTESTATION=1` to require it, or `0` to skip it.
4. Copies the bundle out of the image and prints the sha256 of the key files. With `KEYMESH_LEDGER=asset-ledger.json` (the CI artifact; needs node), it compares every file.
5. Tags the running web image `keymesh-web:rollback-<old revision>`.
6. Recreates **only** `web` (`--no-deps --no-build --pull never`) with `KEYMESH_WEB_IMAGE=docker.io/<repo>@sha256:…`.
7. Waits until it is healthy. Otherwise it rolls back to the previous image and exits non-zero.

It never touches the host proxy, certificates, DNS, VPN or firewall, and never sets `KEYMESH_FAVICON`. Re-running with the same version or SHA is a no-op once that image is running, for the same platform, and healthy.

An amd64 host can use the same script and tag. This repository does not deploy to or configure the GCE host; doing so is a separate, authorized step.

`KEYMESH_WEB_IMAGE` is not persisted. Pass the value the script prints to any later manual `docker compose … up`; otherwise compose falls back to `keymesh-web:local`.

**Roll back** to any earlier release by deploying its version again, or to the tag the script made below. Images published from `main` before releases moved to tags (`sha-<sha>` signed by `refs/heads/main`) fail the new signer check; redeploying one of those needs an explicit `KEYMESH_VERIFY_ATTESTATION=0`, so prefer the rollback tag or a release.

```sh
sudo KEYMESH_WEB_IMAGE=keymesh-web:rollback-<old revision> \
  docker compose -f deploy/compose.yaml up -d --no-deps --no-build --pull never --force-recreate web
```

**Hashes differ by build host.** A WASM built on the Pi or a Mac has a different sha256 from the CI one for the same source (for example, `057e443` gives `ce70d8c8…` on the Pi and `6f8ec680…` on a Mac). Acceptance is therefore of the **CI artifact by image digest** and its recorded ledger, not of a local rebuild.

## Operate
From the repository root.

```sh
sudo docker compose -p keymesh ps                  # state and health
sudo docker compose -p keymesh logs -f web
sudo docker compose -p keymesh restart web
sudo docker compose -p keymesh stop web            # stop and keep the container
# Local fallback: build web from the current dist (run `npm run build:wasm && npm run build`
# in apps/web first, or the image serves a stale build)
sudo KEYMESH_REVISION=$(git rev-parse HEAD) docker compose -f deploy/compose.yaml up -d --build web
```

**Check from the host.** If the host's own resolver doesn't use the VPN DNS, pin the name (`<vpn-address>` is the address the host proxy listens on; `<flarex-root.crt>` is the public FlareX root):

```sh
curl -sI http://127.0.0.1:4320/                    # web, loopback
curl --cacert <flarex-root.crt> --resolve keymesh.cloud:443:<vpn-address> -I https://keymesh.cloud/
```

## Caveats
- **What each client needs:** (1) resolve `keymesh.cloud` through the VPN DNS 10.8.0.1, and (2) trust the FlareX Root CA. `.cloud` is a real public TLD, so a client off the VPN DNS gets NXDOMAIN, or later possibly a public answer.
- **Client trust is not shown here:** this container doesn't make a phone or laptop trust anything. Gate C stays open until a real enrolled device opens the page with no warning.
