// Static server for the production build. Binds to 127.0.0.1 by default.
// Usage: node scripts/serve.mjs [port]   (default 4310)
//        HOST=192.168.50.100 node scripts/serve.mjs 4310   (explicit LAN preview)
//        TLS_CERT=/path/fullchain.pem TLS_KEY=/path/key.pem [HOST=…] node scripts/serve.mjs 4443
// HOST must be one literal IP address; wildcard binds (0.0.0.0, ::) are refused.
// Without TLS_CERT/TLS_KEY this is plain HTTP: a non-loopback HOST is then not
// a secure context and the app turns password vaults off (see docs/DELIVERY.md).
// With them it serves HTTPS (TLS 1.2+) and adds HSTS. Certificates and keys are
// read from the given paths at start; they are never logged, and must not live
// in the repository (*.pem / *.key are git-ignored).
import { createServer as createHttp } from 'node:http';
import { createServer as createHttps } from 'node:https';
import { isIP } from 'node:net';
import { readFile, realpath, stat } from 'node:fs/promises';
import { readFileSync, realpathSync } from 'node:fs';
import { extname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createFaviconRoute } from './favicon.mjs';

// STATIC_ROOT overrides the build directory (used by scripts/serve.test.mjs).
const root = resolve(process.env.STATIC_ROOT?.trim() || fileURLToPath(new URL('../dist/web/browser', import.meta.url)));
// Containment is checked against the real (symlink-resolved) root.
const realRoot = realpathSync(root);
const port = Number(process.argv[2] ?? process.env.PORT ?? 4310);
const host = process.env.HOST?.trim() || '127.0.0.1';
if (!isIP(host) || /^(0\.0\.0\.0|::|0*:(0*:)*0*)$/.test(host)) {
  console.error(`refusing HOST=${host}: give one literal IP address, not a hostname or wildcard`);
  process.exit(1);
}
const certPath = process.env.TLS_CERT?.trim();
const keyPath = process.env.TLS_KEY?.trim();
if (!!certPath !== !!keyPath) {
  console.error('set both TLS_CERT and TLS_KEY, or neither');
  process.exit(1);
}
const tls = !!certPath;
const loopback = host === '::1' || host.startsWith('127.');
const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
  '.ico': 'image/x-icon',
  '.png': 'image/png',
  '.webmanifest': 'application/manifest+json',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
};
// Browser features: the QR scanner's camera, the clipboard (copy, and the
// optional no-prompt read used to clear only what Keymesh copied) and
// passkeys (WebAuthn) for this origin only; everything else is off.
const PERMISSIONS_POLICY = [
  'camera=(self)',
  'clipboard-read=(self)',
  'clipboard-write=(self)',
  'publickey-credentials-create=(self)',
  'publickey-credentials-get=(self)',
  ...['accelerometer', 'autoplay', 'display-capture', 'encrypted-media', 'fullscreen', 'geolocation', 'gyroscope', 'hid',
    'idle-detection', 'magnetometer', 'microphone', 'midi', 'payment', 'picture-in-picture', 'screen-wake-lock', 'serial',
    'usb', 'web-share', 'xr-spatial-tracking'].map((f) => `${f}=()`),
].join(', ');

const security = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; worker-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  // Every resource is for this origin only (no other site may embed or load it).
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': PERMISSIONS_POLICY,
  'Cache-Control': 'no-store',
  // Only over HTTPS; no includeSubDomains/preload for a private host.
  ...(tls ? { 'Strict-Transport-Security': 'max-age=31536000' } : {}),
};

// Optional favicon lookups (M5 C3): OFF unless KEYMESH_FAVICON=1. Even then
// the app asks only after the user opts in. Host names are never logged.
const favicon = createFaviconRoute({ enabled: process.env.KEYMESH_FAVICON === '1' });

async function faviconRequest(req, res, url) {
  if (req.method !== 'GET') return fail(res, 404);
  const r = await favicon(url).catch(() => ({ status: 404 }));
  if (r.status !== 200) {
    res.writeHead(r.status, { ...security, 'Content-Type': 'text/plain; charset=utf-8' });
    return res.end(r.status === 429 ? 'busy' : r.status === 400 ? 'bad request' : 'not found');
  }
  res.writeHead(200, { ...security, 'Content-Type': 'image/png' }); // security sets Cache-Control: no-store
  res.end(r.body);
}

/** True if `p` is the root itself or strictly below it (separator-aware). */
function inside(p) {
  const rel = relative(realRoot, p);
  return rel === '' || (rel !== '..' && !rel.startsWith('..' + sep) && !isAbsolute(rel));
}

function fail(res, status) {
  res.writeHead(status, security);
  res.end(status === 400 ? 'bad request' : 'not found');
}

/**
 * The real path of `p` if it is a regular file inside the root after
 * resolving symlinks, else null. Used for EVERY file served, including the
 * SPA fallback. (Checked per request; it does not defend against a hostile
 * process rewriting the build directory between this check and the read.)
 */
async function servable(p) {
  try {
    const real = await realpath(p);
    if (!inside(real)) return null;
    return (await stat(real)).isFile() ? real : null;
  } catch {
    return null;
  }
}

/**
 * Serves only regular files whose real path (after resolving symlinks) lies
 * inside the build root. Malformed percent-encoding, NUL and backslashes are
 * 400; anything resolving outside the root is 404 (never the SPA shell);
 * missing extensionless paths inside the root get index.html (client-side
 * routes), which passes the same check; missing file names are 404.
 */
async function handler(req, res) {
  let path;
  let url;
  try {
    url = new URL(req.url ?? '/', 'http://x');
    path = decodeURIComponent(url.pathname);
  } catch {
    return fail(res, 400);
  }
  // Dynamic route: never the SPA shell, never a static file.
  if (path === '/api/favicon') return faviconRequest(req, res, url);
  if (path.startsWith('/api/')) return fail(res, 404);
  if (path.includes('\0') || path.includes('\\')) return fail(res, 400);
  const candidate = resolve(realRoot, '.' + path);
  if (!inside(candidate)) return fail(res, 404);
  try {
    let file;
    if ((await stat(candidate).catch(() => null))?.isFile()) {
      file = await servable(candidate);
    } else if (extname(path) === '') {
      // Only extensionless paths are app routes. A missing file name is a
      // 404, never the shell: the service worker must not cache index.html
      // as ngsw.json, a script chunk or the WASM.
      file = await servable(join(realRoot, 'index.html'));
    } else {
      return fail(res, 404);
    }
    if (!file) return fail(res, 404);
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream', ...security });
    res.end(body);
  } catch {
    fail(res, 404);
  }
}

let server;
if (tls) {
  try {
    server = createHttps({ cert: readFileSync(certPath), key: readFileSync(keyPath), minVersion: 'TLSv1.2' }, handler);
  } catch {
    console.error('cannot load TLS_CERT/TLS_KEY (paths not shown)');
    process.exit(1);
  }
} else {
  server = createHttp(handler);
}

server.listen(port, host, () => {
  const shown = host.includes(':') ? `[${host}]` : host;
  console.log(`serving ${root} on ${tls ? 'https' : 'http'}://${shown}:${port}`);
  if (!loopback && !tls) {
    console.warn('LAN preview: plain HTTP, not a secure context (no Clipboard API, password vaults off; traffic is unencrypted). Synthetic data only.');
  }
});
