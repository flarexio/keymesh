# Delivery: HTTPS for private-network use

Status (M4): HTTPS serving and secure-context gating are implemented and tested on loopback. **Trusted remote-browser access is NOT in place:**
* There is no certificate that the client devices trust.
* Choosing one is a human decision (§4).

Until then, the private-network previews stay plain HTTP and demo-only. Every flow, including password vaults, stays experimental and synthetic-only until independent acceptance.

## 1. Three separate gates

| Gate | What it shows | State |
|---|---|---|
| A. Loopback secure context | `http://127.0.0.1` is a secure context by specification, so password vaults run there for development and E2E | ✅ `npm run e2e` |
| B. TLS mechanics | `serve.mjs` serves HTTPS correctly: TLS 1.2+, a certificate chain that verifies against a CA, hostname and IP SAN checks, HSTS, CSP preserved | ✅ `npm run tls-check` (loopback, throwaway CA) |
| C. Trusted remote browser | A phone or laptop on the LAN/VPN opens `https://…` with **no warning and no flag**, because it trusts the certificate | ❌ blocked: needs §4 |

Passing A or B does not imply C:
* A self-signed certificate, a browser "proceed anyway" click, or a Chromium `--ignore-certificate-errors*` flag is **not** a trusted entry.
* A VPN encrypting the path does not make `http://10.8.0.22` a secure context, and password entry stays disabled there.

## 2. What is implemented

**`apps/web/scripts/serve.mjs`:**
* `TLS_CERT=<pem> TLS_KEY=<pem>` switches to HTTPS, with a minimum of TLS 1.2 and `Strict-Transport-Security: max-age=31536000` (no `includeSubDomains`/`preload`).
* `HOST` must still be one literal IP. Wildcards (`0.0.0.0`, `::`) are refused, and the default is `127.0.0.1`.
* Certificate and key paths are never logged.
* **Static-root containment:**
  * Only regular files whose real path, with symlinks resolved, lies inside the build root are served.
  * The check is separator-aware, so siblings that merely share the root's name prefix are excluded.
  * Malformed percent-encoding, NUL and backslashes are refused with 400. Anything resolving outside the root is a 404, never the SPA shell.
  * Covered by `npm run test:serve` (127.0.0.1:4313, temporary synthetic tree).
  * Servers already running keep the handler they started with until they are restarted. The two HTTP previews were not restarted, because that is not authorised.
* Keys must stay outside the repository; `*.pem` and `*.key` are git-ignored.

**Same-origin delivery, with the CSP preserved:**
* `default-src 'self'`, script `'self' 'wasm-unsafe-eval'` (for the page and the KDF worker), and `worker-src 'self'`.
* No third-party origins, `frame-ancestors 'none'`, and `form-action 'none'`.

**App gating:** password-vault create, unlock, reset and restore require `isSecureContext`. On HTTP LAN/VPN origins they are refused and the password-vault database is never opened; the demo still works. Tested by:
* E2E: a `*.test` hostname mapped to loopback, which is not potentially trustworthy.
* `tls-check`: over HTTPS.

## 3. Verification run (`npm run tls-check`, loopback only)

What the script does:
* Creates a throwaway CA and a server certificate (`keymesh.test` and IP `127.0.0.1`, EC P-256, valid for 2 days) in a fresh temporary directory, and deletes it afterwards.
* Changes no trust store.
* Starts HTTPS on `127.0.0.1:4311` and checks the following:
  * full verification against only the test CA succeeds (TLS 1.3);
  * the IP SAN verifies;
  * HSTS and CSP are present;
  * a TLS 1.2-only client works;
  * `openssl s_client -verify_return_error -verify_hostname` gives return code 0.
* **Negative checks:**
  * the default trust store refuses the certificate (`UNABLE_TO_VERIFY_LEAF_SIGNATURE`);
  * a wrong hostname is refused (`ERR_TLS_CERT_ALTNAME_INVALID`);
  * the server refuses a TLS 1.1 handshake (alert 70, protocol version);
  * Chromium refuses the certificate (`net::ERR_CERT_AUTHORITY_INVALID`), which proves no browser trust was added.
* **Secure-context flow over HTTPS:** pinning only this test key with `--ignore-certificate-errors-spki-list` (a bypass flag, explicitly not trust), the HTTPS origin is a secure context. A password vault is created, locked, reloaded and unlocked there.

**Coverage:** Chromium only. No Firefox, Safari or real phone was available. Trusting a custom CA inside an isolated Chromium profile needs NSS tools (`certutil`), which are not installed. Installing them needs system packages, which are out of scope.

## 4. Decision needed for gate C (choose one)

Rediscovered 2026-11-02:
* **Addresses:** `eth0 192.168.50.100/24`, `tun0 10.8.0.22/24`. The HTTP previews still listen on `:4310` on those two addresses, unchanged.
* **Tooling:** no reverse proxy, ACME client, Tailscale or local CA is installed. Only OpenSSL 3.0.13 is present.

| Option | What it needs | Trust model | Notes |
|---|---|---|---|
| **1. Private CA, enrolled on each client** (recommended for a closed VPN) | Create a CA key, kept offline and outside the repo. Issue a server certificate for a private name and/or `IP:10.8.0.22`. **Install the CA on every client device** (phone and laptop settings) | Only devices you enrolled trust it | Enrolment is a manual, per-device human step. Compromise of the CA key affects only those devices; keep it offline |
| 2. Public domain + ACME DNS-01 | A domain you control, a DNS provider API token, and an ACME client | Public Web PKI; works on all devices without enrolment | New account, credentials and DNS changes: needs separate approval. The name would resolve privately (split DNS or a hosts entry) |
| 3. Tailscale HTTPS (`*.ts.net`) | A Tailscale account and the client on each device | Public CA through Tailscale | New external account and system software: needs approval |

**Proposed operation (not executed; needs approval)**, for option 1 once a certificate exists outside the repo:

```sh
# new tmux session; HTTPS on the VPN address only, a new port, the existing previews untouched
tmux new-session -d -s keymesh-vpn-https \
  'cd /home/jarvis/workspaces/keymesh/apps/web && HOST=10.8.0.22 TLS_CERT=<path>/fullchain.pem TLS_KEY=<path>/key.pem node scripts/serve.mjs 4443'
```

* This binds one literal IP on a new port, changes no firewall, VPN or routes, and does not touch the `:4310` HTTP previews.
* **Acceptance check for gate C:** from an enrolled device, open `https://<name>:4443/` and confirm there is no certificate warning and `isSecureContext === true`. Then create a synthetic vault and unlock it after a reload.

## 5. What HTTPS does not change

* Whoever serves the app's code on each load is trusted. HTTPS only authenticates that server.
* Subresource Integrity, an installed app shell and signed native builds are later options (ADR 0001 §5).
* Until independent acceptance:
  * no real secrets in any vault;
  * the banner "Preview version. Do not store real passwords." stays.
