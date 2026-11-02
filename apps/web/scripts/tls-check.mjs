// Isolated HTTPS check for scripts/serve.mjs (loopback only, throwaway trust).
//
// 1. Creates a one-off test CA and a server certificate for `keymesh.test` +
//    127.0.0.1 with OpenSSL in a fresh temporary directory (deleted at the
//    end). Nothing is added to any system, user or browser trust store.
// 2. Serves dist/ over HTTPS on 127.0.0.1 with that certificate.
// 3. Verifies with FULL verification against only the test CA (Node TLS and
//    `openssl s_client -verify_return_error`): chain, hostname, TLS >= 1.2,
//    and the security headers. Negative checks prove verification is not
//    weakened (unknown CA, wrong hostname and TLS 1.1 are all refused).
// 4. Chromium: refuses the test certificate (it is NOT trusted); then, with
//    the server key pinned via --ignore-certificate-errors-spki-list (an
//    explicit bypass flag, NOT browser trust), confirms the HTTPS origin is a
//    secure context and the password-vault flow works there.
//
// This proves loopback TLS mechanics and secure-context gating only. Trusted
// remote-browser access needs a real certificate the client devices trust
// (see docs/DELIVERY.md). Usage: npm run tls-check   (after npm run build)
import { execFileSync, spawn } from 'node:child_process';
import { createHash, X509Certificate } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { request } from 'node:https';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { chromium } from '@playwright/test';

const PORT = Number(process.env.TLS_CHECK_PORT ?? 4311);
const NAME = 'keymesh.test';
const dir = mkdtempSync(join(process.env.TLS_CHECK_DIR ?? tmpdir(), 'keymesh-tls-'));
let failures = 0;
const check = (name, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}${detail ? ` (${detail})` : ''}`);
  if (!ok) failures++;
};
const ossl = (...args) => execFileSync('openssl', args, { cwd: dir, stdio: ['ignore', 'pipe', 'pipe'] });

function makeCertificates() {
  ossl('req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'ca.key',
    '-out', 'ca.pem', '-days', '2', '-subj', '/CN=Keymesh throwaway test CA',
    '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
  ossl('req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-keyout', 'server.key',
    '-out', 'server.csr', '-subj', `/CN=${NAME}`);
  writeFileSync(join(dir, 'ext.cnf'),
    `basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:${NAME},IP:127.0.0.1\n`);
  ossl('x509', '-req', '-in', 'server.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-CAcreateserial',
    '-out', 'server.pem', '-days', '2', '-extfile', 'ext.cnf');
}

function get(opts) {
  return new Promise((resolve) => {
    const r = request({ host: '127.0.0.1', port: PORT, path: '/', method: 'GET', agent: false, ...opts }, (res) => {
      const protocol = res.socket?.getProtocol?.() ?? null;
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, protocol }));
    });
    r.on('error', (e) => resolve({ error: e.code ?? e.message }));
    r.end();
  });
}

async function waitForServer() {
  for (let i = 0; i < 100; i++) {
    const r = await get({ ca: readFileSync(join(dir, 'ca.pem')), servername: NAME });
    if (r.status) return;
    await new Promise((res) => setTimeout(res, 100));
  }
  throw new Error('server did not start');
}

let server;
const stop = () => {
  server?.kill();
  rmSync(dir, { recursive: true, force: true });
};
process.on('uncaughtException', (e) => {
  console.error(`FAIL unexpected error: ${String(e.message).split('\n')[0]}`);
  stop();
  process.exit(1);
});
try {
  makeCertificates();
  const ca = readFileSync(join(dir, 'ca.pem'));
  server = spawn(process.execPath, ['scripts/serve.mjs', String(PORT)], {
    env: { ...process.env, HOST: '127.0.0.1', TLS_CERT: join(dir, 'server.pem'), TLS_KEY: join(dir, 'server.key') },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  await waitForServer();

  const ok = await get({ ca, servername: NAME });
  check('HTTPS with full verification against the test CA', ok.status === 200, `TLS ${ok.protocol}`);
  check('TLS 1.2 or newer negotiated', ok.protocol === 'TLSv1.3' || ok.protocol === 'TLSv1.2');
  check('HSTS header over HTTPS', /max-age=\d+/.test(ok.headers?.['strict-transport-security'] ?? ''));
  check('CSP preserved', (ok.headers?.['content-security-policy'] ?? '').includes("default-src 'self'"));
  const ip = await get({ ca });
  check('IP SAN verifies too (127.0.0.1)', ip.status === 200);

  const untrusted = await get({ servername: NAME });
  check('refused without the test CA (default trust)', !!untrusted.error, untrusted.error);
  const wrongHost = await get({ ca, servername: 'other.test' });
  check('refused for a hostname not in the certificate', wrongHost.error === 'ERR_TLS_CERT_ALTNAME_INVALID', wrongHost.error);
  const tls12 = await get({ ca, servername: NAME, maxVersion: 'TLSv1.2' });
  check('TLS 1.2 client accepted', tls12.status === 200 && tls12.protocol === 'TLSv1.2', tls12.protocol ?? tls12.error);

  const sClient = (extra) => {
    try {
      return execFileSync('sh', ['-c',
        `openssl s_client -connect 127.0.0.1:${PORT} -servername ${NAME} -CAfile "${join(dir, 'ca.pem')}" ${extra} </dev/null 2>&1`],
      { timeout: 10_000 }).toString();
    } catch (e) {
      return `${e.stdout ?? ''}`;
    }
  };
  const sclient = sClient(`-verify_return_error -verify_hostname ${NAME}`);
  // The server's own floor: a TLS 1.1 offer (client security level lowered
  // so OpenSSL is willing to send it) must fail the handshake.
  const tls11 = sClient("-tls1_1 -cipher 'DEFAULT@SECLEVEL=0'");
  if (process.env.TLS_CHECK_DEBUG) console.log(tls11.split('\n').filter((l) => /error|alert|Protocol|Cipher|CONNECTED/i.test(l)).slice(0, 8).join('\n'));
  check('server refuses a TLS 1.1 handshake (alert 70, no cipher)', /alert protocol version/.test(tls11) && /Cipher is \(NONE\)/.test(tls11));
  check('openssl s_client: Verify return code 0', /Verify return code: 0 \(ok\)/.test(sclient));

  // Chromium: the test certificate is not trusted (no trust store changed).
  const spki = createHash('sha256')
    .update(new X509Certificate(readFileSync(join(dir, 'server.pem'))).publicKey.export({ type: 'spki', format: 'der' }))
    .digest('base64');
  const resolver = `--host-resolver-rules=MAP ${NAME} 127.0.0.1`;
  const plain = await chromium.launch({ args: [resolver] });
  let refused = '';
  try {
    await (await plain.newPage()).goto(`https://${NAME}:${PORT}/`);
  } catch (e) {
    refused = String(e.message).match(/net::ERR_[A-Z_]+/)?.[0] ?? 'error';
  }
  await plain.close();
  check('Chromium does not trust the test certificate', refused.startsWith('net::ERR_CERT'), refused);

  // With the server key pinned (bypass flag, not trust): secure context + flow.
  const pinned = await chromium.launch({ args: [resolver, `--ignore-certificate-errors-spki-list=${spki}`] });
  try {
    const page = await pinned.newPage();
    await page.goto(`https://${NAME}:${PORT}/`);
    check('HTTPS origin is a secure context', await page.evaluate(() => isSecureContext));
    const pw = 'synthetic tls check passphrase';
    await page.getByTestId('create-password').fill(pw);
    await page.getByTestId('create-password-confirm').fill(pw);
    await page.getByTestId('create-protected').click();
    await page.getByTestId('recovery-step').waitFor({ timeout: 30_000 });
    const code = await page.getByTestId('recovery-code').evaluate((el) =>
      Array.from(el.querySelectorAll('span')).map((s) => s.textContent?.trim()).join('-'));
    await page.getByTestId('recovery-saved').check();
    await page.getByTestId('recovery-confirm-input').fill(code);
    await page.getByTestId('recovery-confirm').click();
    await page.locator('[data-key-mode=protected]').waitFor({ timeout: 30_000 });
    await page.getByTestId('lock').click();
    await page.reload();
    await page.getByTestId('unlock-password').fill(pw);
    await page.getByTestId('unlock-protected').click();
    await page.locator('[data-key-mode=protected]').waitFor({ timeout: 30_000 });
    check('password vault create/lock/reload/unlock over HTTPS (SPKI-pinned bypass, not trust)', true);
  } catch (e) {
    check('password vault flow over HTTPS', false, String(e.message).split('\n')[0]);
  } finally {
    await pinned.close();
  }
} catch (e) {
  check('TLS check setup', false, String(e.message).split('\n')[0]);
} finally {
  stop();
}

if (failures) {
  console.error(`${failures} TLS check(s) failed`);
  process.exit(1);
}
console.log('all TLS checks passed (loopback, throwaway CA; NOT proof of trusted remote access)');
