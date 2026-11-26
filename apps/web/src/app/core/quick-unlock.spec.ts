/**
 * PRF output handling (review L-7): the 32-byte PRF result is copied for the
 * core and the browser's own result buffer is zeroed right away, so only the
 * copy (zeroed by the caller after use) holds key material.
 */
import { prfFirst } from './quick-unlock';

function credWith(first: ArrayBuffer | undefined) {
  const ext = { prf: { results: first ? { first } : undefined } };
  return { getClientExtensionResults: () => ext } as unknown as PublicKeyCredential;
}

describe('prfFirst', () => {
  it('returns a copy and zeroes the browser-provided buffer', () => {
    const original = new Uint8Array(32).map((_, i) => i + 1).buffer;
    const out = prfFirst(credWith(original))!;
    expect(Array.from(out)).toEqual(Array.from({ length: 32 }, (_, i) => i + 1));
    expect(out.buffer).not.toBe(original);
    expect(new Uint8Array(original).every((b) => b === 0)).toBe(true);
  });

  it('wrong length or no result: null, and the buffer is still zeroed', () => {
    const short = new Uint8Array(16).fill(7).buffer;
    expect(prfFirst(credWith(short))).toBeNull();
    expect(new Uint8Array(short).every((b) => b === 0)).toBe(true);
    expect(prfFirst(credWith(undefined))).toBeNull();
  });
});
