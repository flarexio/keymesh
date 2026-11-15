/**
 * Automatic, local icon for a Login item: a bundled brand, a private/internal
 * host marker, a keyword category, or a letter avatar, in that order.
 * Deterministic and offline: no lookup ever leaves the browser.
 */
import type { Brand } from './brand-icons';

export type LoginCategory = 'bank' | 'mail' | 'shop' | 'crypto' | 'dev' | 'chat' | 'gov';

export type LoginIcon =
  | { kind: 'brand'; brand: Brand }
  | { kind: 'private' }
  | { kind: 'category'; category: LoginCategory }
  | { kind: 'letter'; letter: string; tone: number };

export const LETTER_TONES = 8;

/** Lower-case ASCII (punycode) host of a URL, or null. Adds https:// to bare hosts. */
export function hostOf(url: string | null | undefined): string | null {
  const raw = url?.trim();
  if (!raw) return null;
  try {
    const u = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null;
    return u.hostname.replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase() || null;
  } catch {
    return null;
  }
}

const PRIVATE_SUFFIXES = ['local', 'lan', 'internal', 'intranet', 'corp', 'home', 'home.arpa', 'localdomain', 'localhost', 'test', 'example', 'invalid'];

function ipv4(host: string): number[] | null {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((n) => n <= 255) ? parts : null;
}

/** Hosts that are never public websites: private/loopback/link-local IPs, single labels, reserved names. */
export function isPrivateHost(host: string): boolean {
  const v4 = ipv4(host);
  if (v4) {
    const [a, b2] = v4;
    return (
      a === 10 || a === 127 || a === 0 ||
      (a === 172 && b2 >= 16 && b2 <= 31) ||
      (a === 192 && b2 === 168) ||
      (a === 169 && b2 === 254) ||
      (a === 100 && b2 >= 64 && b2 <= 127)
    );
  }
  if (host.includes(':')) {
    // IPv6 literal (URL() already normalised it). IPv4-mapped forms follow the v4 rules.
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(host);
    if (mapped) return isPrivateHost(mapped[1]);
    const hex = /^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/.exec(host);
    if (hex) {
      const hi = parseInt(hex[1], 16);
      const lo = parseInt(hex[2], 16);
      return isPrivateHost(`${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`);
    }
    return host === '::1' || host === '::' || /^f[cd]/.test(host) || /^fe[89ab]/.test(host);
  }
  if (!host.includes('.')) return true; // single label: intranet name
  return PRIVATE_SUFFIXES.some((s) => host === s || host.endsWith('.' + s));
}

/** Label left of the (approximate) public suffix: google.com.tw → google. */
function siteLabel(host: string): string | null {
  const labels = host.split('.');
  if (labels.length < 2) return null;
  const sld = new Set(['com', 'co', 'net', 'org', 'gov', 'edu', 'ac', 'or', 'ne', 'go', 'idv']);
  const twoPart = labels.length >= 3 && labels.at(-1)!.length === 2 && sld.has(labels.at(-2)!);
  return labels.at(twoPart ? -3 : -2) ?? null;
}

export function brandFor(host: string, brands: readonly Brand[]): Brand | null {
  let best: { brand: Brand; len: number } | null = null;
  for (const brand of brands) {
    for (const d of brand.domains) {
      if ((host === d || host.endsWith('.' + d)) && (!best || d.length > best.len)) best = { brand, len: d.length };
    }
  }
  if (best) return best.brand;
  const label = siteLabel(host);
  return (label && brands.find((b) => b.names?.includes(label))) || null;
}

const CATEGORY_WORDS: [LoginCategory, string[]][] = [
  ['gov', ['gov', '政府', '戶政', '稅務']],
  ['bank', ['bank', 'banking', 'credit', 'card', 'finance', 'invest', 'securities', 'insurance', 'broker', '銀行', '證券', '保險', '信用卡', '金融']],
  ['crypto', ['wallet', 'crypto', 'coin', 'exchange', 'swap', 'defi', 'chain', '錢包', '交易所', '加密']],
  ['mail', ['mail', 'email', 'webmail', 'smtp', 'imap', '郵件', '信箱', '郵箱']],
  ['shop', ['shop', 'store', 'mart', 'mall', 'market', 'buy', '購物', '商城', '商店']],
  ['dev', ['git', 'dev', 'api', 'console', 'admin', 'server', 'vps', 'cloud', 'host', 'hosting', 'deploy', 'ci', '伺服器', '主機']],
  ['chat', ['chat', 'social', 'forum', 'community', 'message', '論壇', '聊天', '社群']],
];

function categoryFor(host: string | null, title: string): LoginCategory | null {
  const hostLabels = host ? host.split('.').slice(0, -1) : [];
  const words = new Set([...hostLabels.flatMap((l) => l.split('-')), ...title.toLowerCase().split(/[^\p{L}\p{N}]+/u)]);
  const text = title.toLowerCase();
  for (const [cat, keys] of CATEGORY_WORDS) {
    for (const k of keys) {
      if (/^[a-z]+$/.test(k) ? words.has(k) : text.includes(k)) return cat;
    }
  }
  return null;
}

/** FNV-1a, for a stable tone per site. */
function tone(s: string): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) h = Math.imul(h ^ s.charCodeAt(i), 0x01000193);
  return (h >>> 0) % LETTER_TONES;
}

function firstLetter(s: string): string | null {
  const t = s.trim();
  if (!t) return null;
  const seg = typeof Intl.Segmenter === 'function' ? [...new Intl.Segmenter().segment(t)][0]?.segment : [...t][0];
  return seg ? seg.toLocaleUpperCase() : null;
}

/**
 * `brands` is the lazily loaded catalogue (shared/brand-catalog.ts); until it
 * arrives, logins show their category or letter.
 */
export function loginIcon(url: string | null | undefined, title: string, brands: readonly Brand[] = []): LoginIcon {
  const host = hostOf(url);
  if (host) {
    const brand = isPrivateHost(host) ? null : brandFor(host, brands);
    if (brand) return { kind: 'brand', brand };
    if (isPrivateHost(host)) return { kind: 'private' };
  }
  const category = categoryFor(host, title);
  if (category) return { kind: 'category', category };
  const label = host ? (siteLabel(host) ?? host) : '';
  const letter = firstLetter(title) ?? firstLetter(label) ?? '?';
  return { kind: 'letter', letter, tone: tone((host ?? title).toLowerCase()) };
}
