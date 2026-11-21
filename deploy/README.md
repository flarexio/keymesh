# Private HTTPS deployment (Docker)

**Experimental, synthetic data only.**

- **Scope:** the Keymesh web app, served over HTTPS at `https://keymesh.cloud/` on the VPN address 10.8.0.22. Reachable only from devices on the VPN.
- **Not covered:** this is not a production deployment and not a trusted-client (gate C) acceptance; see `docs/DELIVERY.md`.

| Service | Image | Binds | Role |
|---|---|---|---|
| `web` | `$KEYMESH_WEB_IMAGE` (a CI-built Docker Hub image pinned by digest, see below), else `keymesh-web:local` built from `deploy/web.Dockerfile` | `127.0.0.1:4320` (HTTP, loopback only) | `apps/web/scripts/serve.mjs` serving the already-built `apps/web/dist/web/browser` |
| `proxy` | `traefik@sha256:2cd5cc75…` (v3.3.7, pinned) | `10.8.0.22:80`, `10.8.0.22:443`, ping on `127.0.0.1:8082` | Terminates TLS for `keymesh.cloud` and gets or renews its certificate from the FlareX step-ca by ACME (HTTP-01) |

## Design rules
- **Host networking:** Docker publishes no ports and adds no NAT or iptables rules. Each process binds one explicit address, and nothing binds `0.0.0.0`.
- **Traefik:** no dashboard and no API.
- **Hardening:** both containers run with a read-only root filesystem, `no-new-privileges`, `cap_drop: ALL` and `restart: unless-stopped`.
  - `web` runs as uid 1000.
  - `proxy` adds only `NET_BIND_SERVICE`.
  - Neither container mounts the Docker socket, home or repo.
- **What the image holds:** only `serve.mjs` and the built bundle, enforced by the allowlist in `web.Dockerfile.dockerignore`. Rebuild `dist` (`npm run build:wasm && npm run build` in `apps/web`) before building the image, or the image serves a stale build.
- **Kept out of git and the image:** the CA root, the ACME keys and the resolver file come from a local runtime directory, `$KEYMESH_RUNTIME`.
- **Unchanged security behaviour:** `serve.mjs` sets CSP, COOP, nosniff and no-referrer and keeps its SPA containment. Traefik adds HSTS (`max-age=31536000`), `sniStrict`, TLS ≥ 1.2, and an HTTP→HTTPS redirect for `keymesh.cloud` only.

## Runtime directory (`$KEYMESH_RUNTIME`, git-ignored)

| Path | Content | Mode |
|---|---|---|
| `flarex-root-ca.crt` | Public FlareX Root CA (DER SHA-256 `3D:9F:42:AD:…:FC:F5:B2:1B`). Traefik uses it to verify `ca.cloud` (`LEGO_CA_CERTIFICATES`) | 0644 |
| `traefik/resolv.conf` | `nameserver 10.8.0.1`: the VPN DNS, which serves `ca.cloud` and `keymesh.cloud`. The host resolver is unchanged | 0644 |
| `traefik/data/acme.json` | ACME account key, certificate and certificate key. **Never print, copy or commit it** | dir root 0700, file root 0600 |

On this Pi, `KEYMESH_RUNTIME=/home/jarvis/workspaces/keymesh/.supervision/tls-probe`.

## Operate
From the repository root. Docker needs sudo on this host.

```sh
export KEYMESH_RUNTIME=/home/jarvis/workspaces/keymesh/.supervision/tls-probe
# start or update (builds web from the current dist)
sudo KEYMESH_RUNTIME=$KEYMESH_RUNTIME KEYMESH_REVISION=$(git rev-parse --short HEAD) \
  docker compose -f deploy/compose.yaml up -d --build
sudo docker compose -p keymesh ps                  # state and health
sudo docker compose -p keymesh logs -f proxy       # or: web
sudo docker compose -p keymesh restart
sudo docker compose -p keymesh stop                # stop and keep the containers
sudo KEYMESH_RUNTIME=$KEYMESH_RUNTIME docker compose -f deploy/compose.yaml down   # remove the containers; ACME data stays
```

**Check from the Pi.** The Pi's own resolver doesn't use the VPN DNS, so pin the name:

```sh
R=$KEYMESH_RUNTIME/flarex-root-ca.crt
curl --cacert $R --resolve keymesh.cloud:443:10.8.0.22 -I https://keymesh.cloud/
openssl s_client -connect 10.8.0.22:443 -servername keymesh.cloud -CAfile $R -verify_hostname keymesh.cloud </dev/null
```

## CI-built image (Docker Hub)

The preferred way to update `web`: GitHub Actions builds the image from the bundle that passed E2E, and the Pi pulls it by commit and pins it by digest. The local `--build` path above stays as a fallback.

**Flow.**
1. **Build.** `ci.yml` job `web` builds the WASM and Angular bundle, runs unit tests and E2E, then uploads that exact `dist/web/browser` (artifact `web-dist`) with its asset ledger.
2. **Image.** Job `image` (needs `rust` and `web`) downloads the artifact, checks it file by file against the tested ledger, and builds `deploy/web.Dockerfile` for `linux/arm64` (COPY-only, no QEMU). Labels: `org.opencontainers.image.revision` (full commit SHA), `source`, `created`.
3. **Push.** Only on push to `main` or `workflow_dispatch` in `flarexio/keymesh`, and only when the Docker Hub settings below exist, it pushes `docker.io/<DOCKERHUB_REPOSITORY>:sha-<full sha>` (plus `:main` on main; no `latest`) and attests build provenance with `actions/attest-build-provenance` (pushed to the registry and stored on GitHub). Pull requests, including forks, build without logging in or pushing; missing settings only skip the push with a notice.
4. **Record.** The job summary shows the digest and the sha256 of `wasm/keymesh_wasm_bg.wasm`, `main-*.js` and `ngsw.json`. Artifact `asset-ledger` (`asset-ledger.json`) lists every bundle file with sha256 and size.
5. **Deploy.** On the Pi, `deploy/pull-deploy.sh <full sha>` (below).

**One-time setup (FlareX; Claude never creates or handles tokens).**
1. Create the Docker Hub repository, e.g. `<namespace>/keymesh-web`.
2. Create a Docker Hub access token with **Read & Write** scope.
3. In GitHub, *Settings → Secrets and variables → Actions*: add the secrets `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`, and the variable `DOCKERHUB_REPOSITORY` = `<namespace>/keymesh-web`.

**Registry login on the Pi.** A public Docker Hub repository needs no login. A private one needs a one-time `sudo docker login` by FlareX, with a token that can read the repository (Read-only scope is enough). Don't put tokens in this repository, shell history or scripts.

**Deploy a commit.**

```sh
export KEYMESH_RUNTIME=/home/jarvis/workspaces/keymesh/.supervision/tls-probe
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

It never touches the proxy, certificates, `$KEYMESH_RUNTIME` contents, DNS, VPN or firewall, and never sets `KEYMESH_FAVICON`. Re-running with the same SHA is a no-op once that image is running and healthy.

`KEYMESH_WEB_IMAGE` is not persisted. Pass the value the script prints to any later manual `docker compose … up` of web; otherwise compose falls back to `keymesh-web:local`.

**Roll back manually** to any earlier CI image by deploying its SHA again, or to the tag the script made:

```sh
sudo KEYMESH_RUNTIME=$KEYMESH_RUNTIME KEYMESH_WEB_IMAGE=keymesh-web:rollback-<old revision> \
  docker compose -f deploy/compose.yaml up -d --no-deps --no-build --pull never --force-recreate web
```

**Hashes differ by build host.** A WASM built on the Pi or a Mac has a different sha256 from the CI one for the same source (for example, `057e443` gives `ce70d8c8…` on the Pi and `6f8ec680…` on a Mac). Acceptance is therefore of the **CI artifact by image digest** and its recorded ledger, not of a local rebuild.

## Caveats
- **The VPN must be up:** `proxy` binds 10.8.0.22. If tun0 isn't up yet at boot, it fails to bind, and Docker retries it until the address exists.
- **Certificate renewal:** step-ca issues 90-day leaves, and Traefik renews `keymesh.cloud` automatically while running. Renewal needs the CA at 10.8.0.1 to reach 10.8.0.22:80.
- **What each client needs:** (1) resolve `keymesh.cloud` through the VPN DNS 10.8.0.1, and (2) trust the FlareX Root CA. `.cloud` is a real public TLD, so a client off the VPN DNS gets NXDOMAIN, or later possibly a public answer.
- **Client trust is not shown here:** these containers don't make a phone or laptop trust anything. Gate C stays open until a real enrolled device opens the page with no warning.
