// Static server for the production build. Binds to 127.0.0.1 by default.
// Usage: node scripts/serve.mjs [port]   (default 4310)
//        HOST=192.168.50.100 node scripts/serve.mjs 4310   (explicit LAN preview)
// HOST must be one literal IP address; wildcard binds (0.0.0.0, ::) are refused.
// A non-loopback HOST is plain HTTP and not a secure context: see README.
import { createServer } from 'node:http';
import { isIP } from 'node:net';
import { readFile, stat } from 'node:fs/promises';
import { extname, join, normalize, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(fileURLToPath(new URL('../dist/web/browser', import.meta.url)));
const port = Number(process.argv[2] ?? process.env.PORT ?? 4310);
const host = process.env.HOST?.trim() || '127.0.0.1';
if (!isIP(host) || /^(0\.0\.0\.0|::|0*:(0*:)*0*)$/.test(host)) {
  console.error(`refusing HOST=${host}: give one literal IP address, not a hostname or wildcard`);
  process.exit(1);
}
const loopback = host === '::1' || host.startsWith('127.');
const types = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.wasm': 'application/wasm',
  '.ico': 'image/x-icon',
  '.json': 'application/json',
  '.txt': 'text/plain; charset=utf-8',
};
const security = {
  'Content-Security-Policy':
    "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'none'; frame-ancestors 'none'",
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cache-Control': 'no-store',
};

createServer(async (req, res) => {
  try {
    const path = decodeURIComponent(new URL(req.url ?? '/', 'http://x').pathname);
    let file = normalize(join(root, path));
    if (!file.startsWith(root)) throw new Error('outside root');
    if (!(await stat(file).catch(() => null))?.isFile()) file = join(root, 'index.html');
    const body = await readFile(file);
    res.writeHead(200, { 'Content-Type': types[extname(file)] ?? 'application/octet-stream', ...security });
    res.end(body);
  } catch {
    res.writeHead(404, security);
    res.end('not found');
  }
}).listen(port, host, () => {
  const shown = host.includes(':') ? `[${host}]` : host;
  console.log(`serving ${root} on http://${shown}:${port}`);
  if (!loopback) {
    console.warn('LAN preview: plain HTTP, not a secure context (no Clipboard API; traffic is unencrypted). Synthetic data only.');
  }
});
