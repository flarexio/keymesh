/**
 * Error → localized message mapping: known conditions get specific keys,
 * anything else a generic message that never echoes the raw error text.
 */
import { errorKey } from './errors';
import { en } from './i18n/en';
import { zhTW } from './i18n/zh-tw';
import { LockedError, StaleWorkError, VaultError } from './vault.service';
import { ConflictError } from './vault-store';

describe('errorKey', () => {
  it('maps app errors by class and code', () => {
    expect(errorKey(new LockedError())).toBe('errors.locked');
    expect(errorKey(new StaleWorkError())).toBe('errors.cancelled');
    expect(errorKey(new ConflictError())).toBe('errors.conflict');
    expect(errorKey(new ConflictError('x', 'staleTab'))).toBe('errors.staleTab');
    expect(errorKey(new VaultError('backupRejected', 'Backup rejected: decryption failed'))).toBe(
      'errors.backupRejected',
    );
    expect(errorKey(new VaultError('ephemeralKeyLost', 'x'))).toBe('errors.ephemeralKeyLost');
    expect(errorKey(new DOMException('denied', 'NotAllowedError'))).toBe('errors.clipboard');
  });

  it('maps known core (Rust/WASM) messages', () => {
    const cases: [string, string][] = [
      ['decryption failed: wrong key or corrupted data', 'errors.decrypt'],
      ['unsupported or unknown format: vault would exceed the maximum size; the change was discarded', 'errors.vaultTooLarge'],
      ['unsupported or unknown format: vault exceeds the maximum size', 'errors.vaultTooLarge'],
      ['unsupported or unknown format: not a keymesh vault', 'errors.format'],
      ['vault integrity check failed: malformed manifest', 'errors.integrity'],
      ['validation failed: title length must be 1..=200', 'errors.titleLength'],
      ['validation failed: username length must be 1..=500', 'errors.fieldLength'],
      ['validation failed: notes exceeds 65536 bytes', 'errors.fieldTooLarge'],
      ['validation failed: urls has more than 100 entries', 'errors.fieldTooLarge'],
      ['validation failed: title contains control characters', 'errors.controlChars'],
      ['validation failed: invalid email address', 'errors.invalidEmail'],
      ['validation failed: url contains whitespace', 'errors.invalidUrl'],
      ['validation failed: contact has no name or contact details', 'errors.contactEmpty'],
      ['validation failed: secret is required', 'errors.secretRequired'],
      ['validation failed: custom field needs a value', 'errors.customValue'],
      ['TOTP error: invalid Base32 secret', 'errors.totpSecret'],
      ['TOTP error: HOTP is not supported', 'errors.totpSetup'],
      ['invalid generator policy: secret size must be 16..=1024 bytes', 'errors.secretSize'],
      ['invalid generator policy: unknown encoding', 'errors.generatorPolicy'],
      ['invalid generator policy: length must be 8..=128', 'errors.pwLength'],
      ['invalid generator policy: select at least one character class', 'errors.pwNoClass'],
      ['invalid generator policy: symbol set is empty', 'errors.pwSymbolsEmpty'],
      ['invalid generator policy: symbol set is too long (at most 64 characters)', 'errors.pwSymbolsLong'],
      ['invalid generator policy: symbol set may only contain ASCII punctuation', 'errors.pwSymbolChars'],
      ['invalid generator policy: character class is empty', 'errors.pwClassEmpty'],
      ['invalid generator policy: policy entropy below 64 bits', 'errors.pwWeak'],
      ['invalid generator policy: malformed password options', 'errors.generatorPolicy'],
      ['item not found', 'errors.notFound'],
    ];
    for (const [message, key] of cases) expect(errorKey(new Error(message)), message).toBe(key);
  });

  it('never surfaces unknown error text, which may carry secret material', () => {
    const leaky = new Error('unexpected token near "SYNTHMARK-PW-0001"');
    const key = errorKey(leaky);
    expect(key).toBe('errors.unexpected');
    expect(en[key]).not.toContain('SYNTHMARK');
    expect(errorKey('SYNTHMARK string thrown')).toBe('errors.unexpected');
    expect(errorKey(undefined)).toBe('errors.unexpected');
    expect(errorKey({ message: 'decryption failed' })).toBe('errors.unexpected');
  });

  it('only produces keys that exist in both catalogs', () => {
    const samples = [
      new LockedError(),
      new StaleWorkError(),
      new ConflictError(),
      ...(['noStoredVault', 'ephemeralKeyLost', 'restoreNotAllowed', 'backupTooLarge', 'backupRejected'] as const).map(
        (c) => new VaultError(c, c),
      ),
      new Error('validation failed: recovery code is empty'),
      new Error('nonsense'),
    ];
    for (const e of samples) {
      const key = errorKey(e);
      expect(en[key], key).toBeTruthy();
      expect(zhTW[key], key).toBeTruthy();
    }
  });
});
