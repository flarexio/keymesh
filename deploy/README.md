# Private HTTPS deployment (Docker)

**Experimental, synthetic data only.**

- **Scope:** the Keymesh web app, served over HTTPS at `https://keymesh.cloud/` on the VPN address 10.8.0.22. Reachable only from devices on the VPN.
- **Not covered:** this is not a production deployment and not a trusted-client (gate C) acceptance; see `docs/DELIVERY.md`.

| Service | Image | Binds | Role |
|---|---|---|---|
| `web` | `keymesh-web:local`, built from `deploy/web.Dockerfile` | `127.0.0.1:4320` (HTTP, loopback only) | `apps/web/scripts/serve.mjs` serving the already-built `apps/web/dist/web/browser` |
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

## Caveats
- **The VPN must be up:** `proxy` binds 10.8.0.22. If tun0 isn't up yet at boot, it fails to bind, and Docker retries it until the address exists.
- **Certificate renewal:** step-ca issues 90-day leaves, and Traefik renews `keymesh.cloud` automatically while running. Renewal needs the CA at 10.8.0.1 to reach 10.8.0.22:80.
- **What each client needs:** (1) resolve `keymesh.cloud` through the VPN DNS 10.8.0.1, and (2) trust the FlareX Root CA. `.cloud` is a real public TLD, so a client off the VPN DNS gets NXDOMAIN, or later possibly a public answer.
- **Client trust is not shown here:** these containers don't make a phone or laptop trust anything. Gate C stays open until a real enrolled device opens the page with no warning.
