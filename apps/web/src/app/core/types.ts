/** Mirrors the JSON views produced by crates/keymesh-wasm (bridge.rs). */

export type ItemKind =
  | 'login'
  | 'secret'
  | 'contact'
  | 'crypto_wallet'
  | 'ed25519_key'
  | 'totp'
  | 'secure_note';

export const KIND_LABELS: Record<ItemKind, string> = {
  login: 'Login',
  secret: 'Secret / API credential',
  contact: 'Contact',
  crypto_wallet: 'Crypto wallet record',
  ed25519_key: 'Ed25519 key',
  totp: 'TOTP',
  secure_note: 'Secure note',
};

export const KINDS = Object.keys(KIND_LABELS) as ItemKind[];

export interface Summary {
  id: string;
  kind: ItemKind;
  title: string;
  subtitle: string | null;
  tags: string[];
}

export interface SecretSlot {
  key: string;
  label: string;
}

export interface CustomView {
  index: number;
  label: string;
  section: string | null;
  concealed: boolean;
  value: string | null;
}

export interface Labeled {
  label: string | null;
  value: string;
}

export interface ItemView {
  id: string;
  kind: ItemKind;
  rev: number;
  title: string;
  tags: string[];
  created_at: number;
  updated_at: number;
  imported: boolean;
  // Kind-specific, non-secret data; see bridge.rs `view`.
  data: Record<string, unknown>;
  secrets: SecretSlot[];
  custom_fields: CustomView[];
}

export interface CustomFieldInput {
  label: string;
  concealed: boolean;
  value: string | null;
  existing: number | null;
}

/** `null` = keep (on update) / absent (on create); `''` = clear. */
export type SecretInput = string | null;

export type DataInput =
  | {
      kind: 'login';
      username: string | null;
      password: SecretInput;
      urls: string[];
      totp_item: string | null;
      recovery_codes: string[] | null;
    }
  | { kind: 'secret'; secret: SecretInput; username: string | null; service: string | null }
  | {
      kind: 'contact';
      full_name: string | null;
      organization: string | null;
      emails: Labeled[];
      phones: Labeled[];
      addresses: Labeled[];
      websites: Labeled[];
    }
  | {
      kind: 'crypto_wallet';
      wallet_software: string | null;
      network: string | null;
      addresses: Labeled[];
      recovery_phrase: SecretInput;
      wallet_password: SecretInput;
      private_key: SecretInput;
      derivation_path: string | null;
    }
  | { kind: 'secure_note'; body: SecretInput }
  | { kind: 'totp'; issuer: string | null; account_name: string | null }
  | { kind: 'ed25519_key'; comment: string | null };

export interface ItemInput {
  title: string;
  tags: string[];
  notes: SecretInput;
  custom_fields: CustomFieldInput[];
  data: DataInput;
}

export interface EnvelopeInfo {
  vault_id: string;
  kek_id: string;
  revision: number;
}

export const FIXTURE_KEY_ID = 'synthetic-fixture-v1';
export const EPHEMERAL_KEY_ID = 'browser-ephemeral-demo-v1';
