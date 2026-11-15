/**
 * WebAuthn PRF plumbing for quick unlock (M5 C1; ADR 0003 §4.1). Only
 * browser glue: every security decision (slot binding, UV/rpIdHash checks,
 * KEK derivation, wrapping) is made by the Rust core. A WebAuthn assertion
 * is a signature, not a key; only the PRF output (32 bytes) is key material,
 * and it is zeroed right after the core used it.
 *
 * Capability: `getClientCapabilities()` is a hint only (absent, rejected or
 * missing key = unknown). The real create()/get() results decide.
 */
import { InjectionToken } from '@angular/core';

export interface WebAuthnPort {
  create(options: CredentialCreationOptions): Promise<Credential | null>;
  get(options: CredentialRequestOptions): Promise<Credential | null>;
  /** `extension:prf` from getClientCapabilities, or undefined if unknown. */
  prfHint(): Promise<boolean | undefined>;
  available(): boolean;
}

export const WEBAUTHN = new InjectionToken<WebAuthnPort>('keymesh.webauthn', {
  providedIn: 'root',
  factory: () => ({
    create: (o) => navigator.credentials.create(o),
    get: (o) => navigator.credentials.get(o),
    async prfHint() {
      try {
        const pkc = globalThis.PublicKeyCredential as unknown as { getClientCapabilities?: () => Promise<Record<string, boolean>> };
        if (typeof pkc?.getClientCapabilities !== 'function') return undefined;
        const caps = await pkc.getClientCapabilities();
        return typeof caps['extension:prf'] === 'boolean' ? caps['extension:prf'] : undefined;
      } catch {
        return undefined;
      }
    },
    available: () => typeof globalThis.PublicKeyCredential === 'function' && !!navigator.credentials,
  }),
});

export const b64u = {
  encode(b: ArrayBuffer | Uint8Array): string {
    const u = b instanceof Uint8Array ? b : new Uint8Array(b);
    let s = '';
    for (const x of u) s += String.fromCharCode(x);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  },
  decode(s: string): Uint8Array<ArrayBuffer> {
    const t = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
    const u = new Uint8Array(new ArrayBuffer(t.length));
    for (let i = 0; i < t.length; i++) u[i] = t.charCodeAt(i);
    return u;
  },
};

/** Stored quick-unlock slot (public), from the core. */
export interface PrfSlotInfo {
  slot_id: string;
  credential_id: string;
  rp_id: string;
  salt: string;
  label: string;
  be: boolean;
}

interface PrfExtOut {
  prf?: { enabled?: boolean; results?: { first?: ArrayBuffer } };
}

export const FLAG_UV = 0x04;
export const FLAG_BE = 0x08;

/** The 32-byte PRF output of a credential result, or null. */
export function prfFirst(cred: PublicKeyCredential): Uint8Array | null {
  const ext = cred.getClientExtensionResults() as PrfExtOut;
  const first = ext.prf?.results?.first;
  if (!first) return null;
  const u = new Uint8Array(first.slice(0));
  return u.length === 32 ? u : null;
}

export function prfEnabled(cred: PublicKeyCredential): boolean {
  return (cred.getClientExtensionResults() as PrfExtOut).prf?.enabled === true;
}

export function flagsOf(authData: ArrayBuffer | Uint8Array): number {
  const u = authData instanceof Uint8Array ? authData : new Uint8Array(authData);
  return u.length >= 33 ? u[32] : 0;
}

export function randomBytes(n: number): Uint8Array<ArrayBuffer> {
  const u = new Uint8Array(new ArrayBuffer(n));
  crypto.getRandomValues(u);
  return u;
}
