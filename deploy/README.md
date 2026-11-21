# Private HTTPS deployment (Docker)

**Experimental, synthetic data only.**

- **Scope:** the Keymesh web app, served as `https://keymesh.cloud/` to devices on the VPN.
- **Not covered:** this is not a production deployment and not a trusted-client (gate C) acceptance; see `docs/DELIVERY.md`.

**Keymesh ships only the web container.** TLS, certificates and routing belong to the host's shared reverse proxy (a Traefik that serves several sites), which is **not part of this repository**.

| Service | Image | Binds | Role |
|---|---|---|---|
| `web` | `$KEYMESH_WEB_IMAGE` (a CI-built Docker Hub image pinned by digest, see below), else `keymesh-web:local` built from `deploy/web.Dockerfile` | `127.0.0.1:4320` (HTTP, loopback only) | `apps/web/scripts/serve.mjs` serving the already-built `apps/web/dist/web/browser` |

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

The preferred way to update `web`: GitHub Actions builds the image from the bundle that passed E2E, and the host pulls it by commit and pins it by digest.

**Flow.**
1. **Build.** `ci.yml` job `web` builds the WASM and Angular bundle, runs unit tests and E2E, then uploads that exact `dist/web/browser` (artifact `web-dist`) with its asset ledger.
2. **Image.** Job `image` (needs `rust` and `web`) downloads the artifact, checks it file by file against the tested ledger, and builds `deploy/web.Dockerfile` for `linux/arm64` (COPY-only, no QEMU). Labels: `org.opencontainers.image.revision` (full commit SHA), `source`, `created`.
3. **Push.** Only on push to `main` or `workflow_dispatch` in `flarexio/keymesh`, and only when the Docker Hub settings below exist, it pushes `docker.io/<DOCKERHUB_REPOSITORY>:sha-<full sha>` (plus `:main` on main; no `latest`) and attests build provenance with `actions/attest-build-provenance` (pushed to the registry and stored on GitHub). Pull requests, including forks, build without logging in or pushing; missing settings only skip the push with a notice.
4. **Record.** The job summary shows the digest and the sha256 of `wasm/keymesh_wasm_bg.wasm`, `main-*.js` and `ngsw.json`. Artifact `asset-ledger` (`asset-ledger.json`) lists every bundle file with sha256 and size.
5. **Deploy.** On the host, `deploy/pull-deploy.sh <full sha>` (below).

**One-time setup (FlareX; Claude never creates or handles tokens).**
1. Create the Docker Hub repository, e.g. `<namespace>/keymesh-web`.
2. Create a Docker Hub access token with **Read & Write** scope.
3. In GitHub, *Settings → Secrets and variables → Actions*: add the secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, and the variable `DOCKERHUB_REPOSITORY` = `<namespace>/keymesh-web`.

**Registry login on the host.** A public Docker Hub repository needs no login. A private one needs a one-time `sudo docker login` by FlareX, with a token that can read the repository (Read-only scope is enough). Don't put tokens in this repository, shell history or scripts.

**Deploy a commit** (from the repository root; Docker needs sudo on the host):

```sh
KEYMESH_IMAGE_REPO=<namespace>/keymesh-web deploy/pull-deploy.sh <full 40-hex sha>
```

The script, using `sudo docker`:
1. Pulls `docker.io/<repo>:sha-<sha>` and pins it by digest.
2. **Refuses** unless the revision label is exactly `<sha>` and the platform is `linux/arm64`.
3. Runs `gh attestation verify oci://docker.io/<repo>@sha256:… --repo flarexio/keymesh` when `gh` is installed. Set `KEYMESH_VERIFY_ATTESTATION=1` to require it, or `0` to skip it.
4. Copies the bundle out of the image and prints the sha256 of the key files. With `KEYMESH_LEDGER=asset-ledger.json` (the CI artifact; needs node), it compares every file.
5. Tags the running web image `keymesh-web:rollback-<old revision>`.
6. Recreates **only** `web` (`--no-deps --no-build --pull never`) with `KEYMESH_WEB_IMAGE=docker.io/<repo>@sha256:…`.
7. Waits until it is healthy. Otherwise it rolls back to the previous image and exits non-zero.

It never touches the host proxy, certificates, DNS, VPN or firewall, and never sets `KEYMESH_FAVICON`. Re-running with the same SHA is a no-op once that image is running and healthy.

`KEYMESH_WEB_IMAGE` is not persisted. Pass the value the script prints to any later manual `docker compose … up`; otherwise compose falls back to `keymesh-web:local`.

**Roll back** to any earlier CI image by deploying its SHA again, or to the tag the script made:

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
