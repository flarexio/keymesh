/**
 * Maps any thrown value to a localized message key.
 *
 * Only known, secret-free conditions get a specific message. Everything else
 * becomes a generic "unexpected error": raw low-level messages are never
 * shown or logged, since a future dependency could put input into them.
 */
import type { MessageKey } from './i18n/i18n.service';
import { LockedError, StaleWorkError, VaultError } from './vault.service';
import { ConflictError } from './vault-store';

/** Core (Rust/WASM) error text → key. Matched on fixed English fragments. */
const CORE_PATTERNS: [RegExp, MessageKey][] = [
  [/^decryption failed/, 'errors.decrypt'],
  [/^validation failed: password is (too short|empty)/, 'errors.passwordShort'],
  [/^validation failed: password is too long/, 'errors.passwordLong'],
  [/^validation failed: password is too common/, 'errors.passwordCommon'],
  [/^validation failed: recovery code is not valid/, 'errors.recoveryInvalid'],
  [/^unsupported or unknown format: unsupported recovery code version/, 'errors.recoveryInvalid'],
  [/^validation failed: recovery code does not match/, 'errors.recoveryMismatch'],
  [/^unsupported or unknown format: this is a demo vault/, 'errors.demoBackup'],
  [/^unsupported or unknown format: this vault opens with its password/, 'errors.protectedBackup'],
  [/^unsupported or unknown format: vault (would )?exceeds? the maximum/, 'errors.vaultTooLarge'],
  [/^unsupported or unknown format/, 'errors.format'],
  [/^vault integrity check failed/, 'errors.integrity'],
  [/^validation failed: title length/, 'errors.titleLength'],
  [/^validation failed: .* contains control characters/, 'errors.controlChars'],
  [/^validation failed: .* (exceeds \d+ bytes|has more than \d+ entries)/, 'errors.fieldTooLarge'],
  [/^validation failed: .* length must be/, 'errors.fieldLength'],
  [/^validation failed: invalid email address/, 'errors.invalidEmail'],
  [/^validation failed: url contains whitespace/, 'errors.invalidUrl'],
  [/^validation failed: contact has no name or contact details/, 'errors.contactEmpty'],
  [/^validation failed: (secret is required|secret is empty)/, 'errors.secretRequired'],
  [/^validation failed: recovery code is empty/, 'errors.recoveryCodeEmpty'],
  [/^validation failed: (generated value is no longer available|unknown preview)/, 'errors.previewGone'],
  [/^validation failed: custom field needs a value/, 'errors.customValue'],
  [/^validation failed: vault is locked/, 'errors.locked'],
  [/^TOTP error: (empty Base32 secret|invalid Base32 secret|secret)/, 'errors.totpSecret'],
  [/^TOTP error/, 'errors.totpSetup'],
  [/^invalid generator policy: secret size/, 'errors.secretSize'],
  [/^invalid generator policy: length must be/, 'errors.pwLength'],
  [/^invalid generator policy: select at least one character class/, 'errors.pwNoClass'],
  [/^invalid generator policy: symbol set is empty/, 'errors.pwSymbolsEmpty'],
  [/^invalid generator policy: symbol set is too long/, 'errors.pwSymbolsLong'],
  [/^invalid generator policy: symbol set may only contain/, 'errors.pwSymbolChars'],
  [/^invalid generator policy: character class is empty/, 'errors.pwClassEmpty'],
  [/^invalid generator policy: policy entropy below/, 'errors.pwWeak'],
  [/^invalid generator policy/, 'errors.generatorPolicy'],
  [/^item not found/, 'errors.notFound'],
  [/^Ed25519 key error/, 'errors.signFailed'],
];

export function errorKey(e: unknown): MessageKey {
  if (e instanceof StaleWorkError) return e.committed ? 'errors.lockedAfterSave' : 'errors.cancelled';
  if (e instanceof LockedError) return 'errors.locked';
  if (e instanceof VaultError) return `errors.${e.code}`;
  if (e instanceof ConflictError) return e.code === 'staleTab' ? 'errors.staleTab' : 'errors.conflict';
  if (e instanceof DOMException && e.name === 'NotAllowedError') return 'errors.clipboard';
  const text = e instanceof Error ? e.message : '';
  for (const [re, key] of CORE_PATTERNS) if (re.test(text)) return key;
  return 'errors.unexpected';
}
