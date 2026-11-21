import { QR_MAX_TEXT, classifyQrText } from './otpauth-qr';

// RFC 6238 test-vector secret: synthetic, public.
const SECRET = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';

describe('QR text classification', () => {
  it('accepts a TOTP URI and pre-fills issuer and account from it', () => {
    const uri = `otpauth://totp/Example%20Co:alice%40example.test?secret=${SECRET}&issuer=Example%20Co`;
    expect(classifyQrText(uri)).toEqual({ kind: 'totp', uri, issuer: 'Example Co', account: 'alice@example.test' });
  });

  it('falls back to the label prefix when there is no issuer parameter', () => {
    expect(classifyQrText(`OTPAUTH://TOTP/Acme:bob?secret=${SECRET}`)).toMatchObject({ kind: 'totp', issuer: 'Acme', account: 'bob' });
    expect(classifyQrText(`otpauth://totp/bob?secret=${SECRET}`)).toMatchObject({ kind: 'totp', issuer: null, account: 'bob' });
  });

  it('rejects everything that is not a TOTP setup, without returning its content', () => {
    expect(classifyQrText(`otpauth://hotp/x?secret=${SECRET}&counter=1`)).toEqual({ kind: 'hotp' });
    expect(classifyQrText('otpauth-migration://offline?data=AAAA')).toEqual({ kind: 'migration' });
    expect(classifyQrText('https://example.test/login')).toEqual({ kind: 'other' });
    expect(classifyQrText('WIFI:S:net;T:WPA;P:synthetic;;')).toEqual({ kind: 'other' });
    expect(classifyQrText('javascript:alert(1)')).toEqual({ kind: 'other' });
    expect(classifyQrText('  ')).toEqual({ kind: 'empty' });
    expect(classifyQrText(null)).toEqual({ kind: 'empty' });
    expect(classifyQrText('otpauth://totp/x?secret=' + 'A'.repeat(QR_MAX_TEXT))).toEqual({ kind: 'tooLong' });
  });

  it('a malformed TOTP URI is still handed to the core (which reports the error)', () => {
    expect(classifyQrText('otpauth://totp/%E0%A4%A?secret=x')).toMatchObject({ kind: 'totp', issuer: null, account: null });
  });
});
