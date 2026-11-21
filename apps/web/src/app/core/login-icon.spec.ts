import { BRANDS } from './brand-icons';
import { LETTER_TONES, brandFor, hostOf, isPrivateHost, loginIcon } from './login-icon';

const brandOf = (url: string, title = 'x') => {
  const i = loginIcon(url, title, BRANDS);
  return i.kind === 'brand' ? i.brand.title : i.kind;
};

describe('login icons (local only)', () => {
  it('parses hosts from full URLs and bare hosts, never from other schemes', () => {
    expect(hostOf('https://User:pw@GitHub.com:8443/a?b#c')).toBe('github.com');
    expect(hostOf('github.com/login')).toBe('github.com');
    expect(hostOf('http://[::1]:8080/')).toBe('::1');
    expect(hostOf('https://bücher.example')).toBe('xn--bcher-kva.example');
    expect(hostOf('javascript:alert(1)')).toBeNull();
    expect(hostOf('ftp://files.example.test')).toBeNull();
    expect(hostOf('')).toBeNull();
    expect(hostOf(null)).toBeNull();
  });

  it('matches bundled brands by domain, longest match first, and by site label', () => {
    expect(brandOf('https://github.com/login')).toBe('GitHub');
    expect(brandOf('https://gist.github.com')).toBe('GitHub');
    expect(brandOf('https://mail.google.com/mail/u/0')).toBe('Gmail');
    expect(brandOf('https://console.cloud.google.com')).toBe('Google Cloud');
    expect(brandOf('https://accounts.google.com')).toBe('Google');
    expect(brandOf('https://www.google.com.tw')).toBe('Google');
    expect(brandOf('https://shopee.tw')).toBe('Shopee');
    expect(brandOf('https://twitter.com')).toBe('X');
    expect(brandOf('https://www.google.co.jp')).toBe('Google');
    expect(brandOf('https://shopee.sg')).toBe('Shopee');
    // Look-alikes and unreviewed TLDs do not match (no label guessing).
    expect(brandFor('google.zip', BRANDS)).toBeNull();
    expect(brandFor('paypal.example.com', BRANDS)).toBeNull();
    expect(brandFor('shopee.evil', BRANDS)).toBeNull();
    // Removed: an icon with its own licence (CC-BY-SA-4.0) is not bundled.
    expect(brandFor('rust-lang.org', BRANDS)).toBeNull();
    expect(BRANDS.length).toBe(81);
    expect(brandFor('notgithub.com', BRANDS)).toBeNull();
    expect(brandFor('github.com.evil.example', BRANDS)).toBeNull();
    // Without the catalogue (not loaded yet) a login still gets a category or letter.
    expect(loginIcon('https://github.com', 'GitHub').kind).toBe('letter');
  });

  it('every bundled brand has a valid colour and path, and unique domains', () => {
    const seen = new Set<string>();
    for (const b of BRANDS) {
      expect(b.hex).toMatch(/^#[0-9a-f]{6}$/i);
      expect(b.path.length).toBeGreaterThan(10);
      for (const d of b.domains) {
        expect(seen.has(d)).toBe(false);
        seen.add(d);
        expect(brandFor(d, BRANDS)?.id).toBe(b.id);
      }
    }
  });

  it('private and internal hosts get the server icon, never a brand', () => {
    for (const host of [
      'http://192.168.50.1', 'https://10.8.0.22', 'http://172.20.1.1', 'http://127.0.0.1:4310', 'http://100.100.1.1',
      'http://169.254.1.1', 'http://[::1]', 'http://[fd00::1]', 'http://[fe80::1]', 'http://[::ffff:10.0.0.1]',
      'http://router', 'https://nas.local', 'https://github.home.arpa', 'https://grafana.lan', 'https://x.internal',
    ]) {
      expect(loginIcon(host, 'x', BRANDS).kind).toBe('private');
    }
    expect(isPrivateHost('8.8.8.8')).toBe(false);
    expect(isPrivateHost('172.32.0.1')).toBe(false);
    expect(isPrivateHost('[2001:db8::1]'.slice(1, -1))).toBe(false);
  });

  it('falls back to a keyword category from host or title (English and Chinese)', () => {
    expect(loginIcon('https://ebanking.example-bank.com', 'x')).toEqual({ kind: 'category', category: 'bank' });
    expect(loginIcon(null, '玉山銀行')).toEqual({ kind: 'category', category: 'bank' });
    expect(loginIcon('https://webmail.example.org', 'Work')).toEqual({ kind: 'category', category: 'mail' });
    expect(loginIcon(null, '我的錢包')).toEqual({ kind: 'category', category: 'crypto' });
    expect(loginIcon('https://www.gov.tw', 'x')).toEqual({ kind: 'category', category: 'gov' });
  });

  it('otherwise a stable letter avatar (title first, then site)', () => {
    const a = loginIcon('https://example.org', 'zebra notes');
    expect(a).toMatchObject({ kind: 'letter', letter: 'Z' });
    expect(loginIcon('https://example.org', 'zebra notes')).toEqual(a);
    expect(loginIcon('https://example.org', '台灣')).toMatchObject({ kind: 'letter', letter: '台' });
    expect(loginIcon('https://example.org', '  ')).toMatchObject({ kind: 'letter', letter: 'E' });
    expect(loginIcon(null, '')).toMatchObject({ kind: 'letter', letter: '?' });
    const t = loginIcon('https://another.example.net', 'q');
    expect(t.kind === 'letter' && t.tone >= 0 && t.tone < LETTER_TONES).toBe(true);
  });
});
