// Asset ledger for a built web bundle: every file under <dir>, keyed by its
// POSIX path relative to <dir>, with sha256 and size. CI writes one for the
// bundle that passed E2E, then rebuilds it from the downloaded artifact and
// compares the two before building the image.
// Usage: node scripts/asset-ledger.mjs <dir> [--out ledger.json] [--revision <sha>]
//        node scripts/asset-ledger.mjs --compare a.json b.json
// The bundle holds only public build output, so the ledger holds nothing secret.
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';

function walk(dir) {
  return readdirSync(dir, { withFileTypes: true, recursive: true })
    .filter((e) => e.isFile())
    .map((e) => join(e.parentPath, e.name));
}

function ledger(dir) {
  const files = {};
  for (const abs of walk(dir).sort()) {
    const data = readFileSync(abs);
    const path = relative(dir, abs).split(sep).join('/');
    files[path] = { sha256: createHash('sha256').update(data).digest('hex'), bytes: data.length };
  }
  return Object.fromEntries(Object.entries(files).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)));
}

function arg(name) {
  const i = process.argv.indexOf(name);
  return i < 0 ? undefined : process.argv[i + 1];
}

const argv = process.argv.slice(2);
if (argv[0] === '--compare') {
  const [a, b] = argv.slice(1, 3).map((p) => JSON.parse(readFileSync(p, 'utf8')).files);
  const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
  const diff = keys.filter((k) => JSON.stringify(a[k]) !== JSON.stringify(b[k]));
  for (const k of diff) console.error(`ledger mismatch: ${k}`);
  console.log(diff.length ? `${diff.length} file(s) differ` : `ledgers match (${keys.length} files)`);
  process.exit(diff.length ? 1 : 0);
} else if (argv[0] && !argv[0].startsWith('--')) {
  const files = ledger(argv[0]);
  if (Object.keys(files).length === 0) {
    console.error(`no files under ${argv[0]}`);
    process.exit(1);
  }
  const out = JSON.stringify({ revision: arg('--revision') ?? null, files }, null, 2) + '\n';
  const target = arg('--out');
  if (target) writeFileSync(target, out);
  else process.stdout.write(out);
} else {
  console.error('usage: asset-ledger.mjs <dir> [--out file] [--revision sha] | --compare a.json b.json');
  process.exit(2);
}
