/**
 * Pure mapping between flat form state and the core's `ItemInput`.
 *
 * Secret fields follow keep / clear / set semantics when editing:
 * an empty input keeps the stored value, the "remove" checkbox clears it,
 * and any text replaces it. On create, empty means absent.
 */
import { CustomFieldInput, ItemInput, ItemKind, ItemView, Labeled, SecretInput } from './types';

export interface CustomRow {
  label: string;
  concealed: boolean;
  value: string;
  /** Index of the stored field this row edits (edit mode). */
  existing: number | null;
}

export interface FormModel {
  title: string;
  tags: string;
  notes: string;
  username: string;
  password: string;
  urls: string;
  totpItem: string;
  recoveryCodes: string;
  secret: string;
  service: string;
  fullName: string;
  organization: string;
  emails: string;
  phones: string;
  addresses: string;
  websites: string;
  walletSoftware: string;
  network: string;
  walletAddresses: string;
  derivationPath: string;
  recoveryPhrase: string;
  walletPassword: string;
  privateKey: string;
  body: string;
  issuer: string;
  accountName: string;
  comment: string;
  /** TOTP create: otpauth URI or Base32 secret. */
  totpSetup: string;
  /** Secret fields the user asked to remove (edit mode). */
  clear: Record<string, boolean>;
  custom: CustomRow[];
}

export function emptyModel(): FormModel {
  return {
    title: '',
    tags: '',
    notes: '',
    username: '',
    password: '',
    urls: '',
    totpItem: '',
    recoveryCodes: '',
    secret: '',
    service: '',
    fullName: '',
    organization: '',
    emails: '',
    phones: '',
    addresses: '',
    websites: '',
    walletSoftware: '',
    network: '',
    walletAddresses: '',
    derivationPath: '',
    recoveryPhrase: '',
    walletPassword: '',
    privateKey: '',
    body: '',
    issuer: '',
    accountName: '',
    comment: '',
    totpSetup: '',
    clear: {},
    custom: [],
  };
}

export function lines(text: string): string[] {
  return text
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l.length > 0);
}

/** One entry per line; optional `label | value`. */
export function labeledLines(text: string): Labeled[] {
  return lines(text).map((l) => {
    const i = l.indexOf(' | ');
    return i > 0
      ? { label: l.slice(0, i).trim() || null, value: l.slice(i + 3).trim() }
      : { label: null, value: l };
  });
}

export function labeledText(v: unknown): string {
  return ((v as Labeled[] | undefined) ?? [])
    .map((x) => (x.label ? `${x.label} | ${x.value}` : x.value))
    .join('\n');
}

export function tags(text: string): string[] {
  return text
    .split(',')
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

function opt(s: string): string | null {
  const t = s.trim();
  return t.length ? t : null;
}

/** Secret value: create → absent if empty; edit → keep if empty. */
function sec(m: FormModel, field: string, value: string, editing: boolean): SecretInput {
  if (editing && m.clear[field]) return '';
  if (value.length === 0) return null;
  return value;
}

function custom(rows: CustomRow[], editing: boolean): CustomFieldInput[] {
  return rows
    .filter((r) => r.label.trim().length > 0)
    .map((r) => ({
      label: r.label.trim(),
      concealed: r.concealed,
      // Editing a stored concealed field: empty keeps its value.
      value: editing && r.existing !== null && r.concealed && r.value === '' ? null : r.value,
      existing: editing ? r.existing : null,
    }))
    .filter((r) => r.value !== null || r.existing !== null);
}

export function buildInput(kind: ItemKind, m: FormModel, editing: boolean): ItemInput {
  const base = {
    title: m.title.trim(),
    tags: tags(m.tags),
    notes: sec(m, 'notes', m.notes, editing),
    custom_fields: custom(m.custom, editing),
  };
  switch (kind) {
    case 'login':
      return {
        ...base,
        data: {
          kind,
          username: opt(m.username),
          password: sec(m, 'password', m.password, editing),
          urls: lines(m.urls),
          totp_item: opt(m.totpItem),
          recovery_codes: editing && m.recoveryCodes === '' && !m.clear['recoveryCodes']
            ? null
            : lines(m.recoveryCodes),
        },
      };
    case 'secret':
      return {
        ...base,
        data: {
          kind,
          secret: m.secret.length ? m.secret : null,
          username: opt(m.username),
          service: opt(m.service),
        },
      };
    case 'contact':
      return {
        ...base,
        data: {
          kind,
          full_name: opt(m.fullName),
          organization: opt(m.organization),
          emails: labeledLines(m.emails),
          phones: labeledLines(m.phones),
          addresses: labeledLines(m.addresses),
          websites: labeledLines(m.websites),
        },
      };
    case 'crypto_wallet':
      return {
        ...base,
        data: {
          kind,
          wallet_software: opt(m.walletSoftware),
          network: opt(m.network),
          addresses: labeledLines(m.walletAddresses),
          recovery_phrase: sec(m, 'recoveryPhrase', m.recoveryPhrase, editing),
          wallet_password: sec(m, 'walletPassword', m.walletPassword, editing),
          private_key: sec(m, 'privateKey', m.privateKey, editing),
          derivation_path: opt(m.derivationPath),
        },
      };
    case 'secure_note':
      return { ...base, data: { kind, body: m.body.length ? m.body : editing ? null : '' } };
    case 'totp':
      return { ...base, data: { kind, issuer: opt(m.issuer), account_name: opt(m.accountName) } };
    case 'ed25519_key':
      return { ...base, data: { kind, comment: opt(m.comment) } };
  }
}

/** Prefill an edit form from a (secret-free) item view. Secret inputs stay
 *  empty: leaving them empty keeps the stored values. */
export function modelFromView(v: ItemView): FormModel {
  const m = emptyModel();
  const d = v.data;
  const str = (k: string) => (typeof d[k] === 'string' ? (d[k] as string) : '');
  m.title = v.title;
  m.tags = v.tags.join(', ');
  m.custom = v.custom_fields.map((c) => ({
    label: c.label,
    concealed: c.concealed,
    value: c.value ?? '',
    existing: c.index,
  }));
  switch (v.kind) {
    case 'login':
      m.username = str('username');
      m.urls = ((d['urls'] as string[] | undefined) ?? []).join('\n');
      m.totpItem = str('totp_item');
      break;
    case 'secret':
      m.username = str('username');
      m.service = str('service');
      break;
    case 'contact':
      m.fullName = str('full_name');
      m.organization = str('organization');
      m.emails = labeledText(d['emails']);
      m.phones = labeledText(d['phones']);
      m.addresses = labeledText(d['addresses']);
      m.websites = labeledText(d['websites']);
      break;
    case 'crypto_wallet':
      m.walletSoftware = str('wallet_software');
      m.network = str('network');
      m.walletAddresses = labeledText(d['addresses']);
      m.derivationPath = str('derivation_path');
      break;
    case 'totp':
      m.issuer = str('issuer');
      m.accountName = str('account_name');
      break;
    case 'ed25519_key':
      m.comment = str('comment');
      break;
    case 'secure_note':
      break;
  }
  return m;
}
