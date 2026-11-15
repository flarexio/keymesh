/**
 * What a decoded QR code may become. Only a TOTP `otpauth://totp/` URI is
 * offered as a TOTP setup; anything else is rejected without showing or
 * storing its content. The URI itself is validated by the Rust core when the
 * item is saved (same path as a typed URI); the label/issuer read here only
 * pre-fill empty, user-editable fields.
 */
export const QR_MAX_TEXT = 2048;

export type QrClassification =
  | { kind: 'totp'; uri: string; issuer: string | null; account: string | null }
  | { kind: 'hotp' | 'migration' | 'other' | 'tooLong' | 'empty' };

const clean = (s: string | null | undefined): string | null => {
  const t = s?.trim();
  return t ? t.slice(0, 200) : null;
};

export function classifyQrText(text: string | null | undefined): QrClassification {
  const t = (text ?? '').trim();
  if (!t) return { kind: 'empty' };
  if (t.length > QR_MAX_TEXT) return { kind: 'tooLong' };
  const lower = t.toLowerCase();
  if (lower.startsWith('otpauth-migration:')) return { kind: 'migration' };
  if (lower.startsWith('otpauth://hotp/')) return { kind: 'hotp' };
  if (!lower.startsWith('otpauth://totp/')) return { kind: 'other' };
  let issuer: string | null = null;
  let account: string | null = null;
  try {
    const u = new URL(t);
    const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
    const colon = label.indexOf(':');
    account = clean(colon >= 0 ? label.slice(colon + 1) : label);
    issuer = clean(u.searchParams.get('issuer')) ?? clean(colon >= 0 ? label.slice(0, colon) : null);
  } catch {
    // Not parseable here: still handed to the core, which reports the error.
  }
  return { kind: 'totp', uri: t, issuer, account };
}
