/**
 * Deterministic orchestration tests for the password vault (envelope v2):
 * a fake core, a KDF whose results are released by hand, and stores whose
 * writes can be held or failed. Real Argon2id/XChaCha20 are covered by the
 * Rust tests, the shared vectors and the browser E2E.
 */
import { TestBed } from '@angular/core/testing';
import { IDBFactory } from 'fake-indexeddb';
import { KDF_RUNNER, KdfCancelledError, KdfRunner } from './kdf';
import { errorKey } from './errors';
import {
  CORE_LOADER,
  PROTECTED_VAULT_STORE,
  SECURE_CONTEXT,
  StaleWorkError,
  VAULT_STORE,
  VaultError,
  VaultService,
} from './vault.service';
import { ConflictError, StoredVault, VaultStore } from './vault-store';
import type { Core } from './wasm';
import { provideServiceWorker } from '@angular/service-worker';
import { App } from '../app';
import { PreferencesService } from './preferences';
import { en } from './i18n/en';
import { zhTW } from './i18n/zh-tw';
import { PREFERENCE_STORAGE } from './preferences';
import { WEBAUTHN } from './quick-unlock';
import { AutoLock, LOCK_CLOCK, COARSE_POINTER, AUTOLOCK_STORAGE } from './auto-lock';

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

/** Wait (bounded) until `cond` holds; fake IndexedDB completes on timers. */
async function until(cond: () => boolean, what = 'condition'): Promise<void> {
  for (let i = 0; i < 200; i++) {
    if (cond()) return;
    await new Promise((r) => setTimeout(r, 1));
  }
  throw new Error(`timed out waiting for ${what}`);
}

const GOOD_PW = 'synthetic good passphrase';
const NEW_PW = 'synthetic newer passphrase';
const CODE = 'GOOD-CODE';
const OTHER_CODE = 'OTHER-CODE';
const ROT_CODE = 'ROTATED-CODE';
const codeTag = (c: string) => (c === CODE ? 1 : c === ROT_CODE ? 2 : 0);

/** v2 envelope stand-in: [1, revision, uniqueness, 2, passwordTag, codeTag]. */
let counter = 0;
const v2 = (revision: number, pw = 1, code = 1) => new Uint8Array([1, revision, ++counter % 256, 2, pw, code]);
const pwTag = (pw: string) => (pw === GOOD_PW ? 1 : pw === NEW_PW ? 2 : 9);

/** The fake "derived key": byte 0 tags which password it came from. */
const keyFor = (pw: string) => new Uint8Array([pwTag(pw), 0, 0, 0]);

const sessions: FakeSession[] = [];
const CRED = new Uint8Array(Array.from({ length: 16 }, (_, i) => i + 1));
const CRED_B64 = 'AQIDBAUGBwgJCgsMDQ4PEA';
const PRF_SLOT = { slot_id: 'aaaaaaaaaaaaaaaa', credential_id: CRED_B64, rp_id: 'localhost', salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', label: 'Synthetic key', be: false };

/** Scripted WebAuthn: create() returns a credential with or without PRF. */
function fakeWebAuthn(opts: { prf?: boolean; hold?: Promise<void> } = {}) {
  const calls = { create: 0, get: 0 };
  const authData = (flags: number) => {
    const d = new Uint8Array(37);
    d[32] = flags;
    return d.buffer;
  };
  const cred = (prf: boolean) =>
    ({
      rawId: CRED.slice().buffer,
      response: { getAuthenticatorData: () => authData(0x05), authenticatorData: authData(0x05) },
      getClientExtensionResults: () => ({ prf: { enabled: prf, results: prf ? { first: new Uint8Array(32).fill(7).buffer } : undefined } }),
    }) as unknown as PublicKeyCredential;
  return {
    calls,
    port: {
      async create(o: CredentialCreationOptions) {
        calls.create++;
        if (opts.hold) {
          await new Promise<void>((res, rej) => {
            o.signal?.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError')));
            void opts.hold!.then(res);
          });
        }
        return cred(opts.prf ?? true);
      },
      async get() {
        calls.get++;
        return opts.prf === false ? cred(false) : cred(true);
      },
      prfHint: async () => undefined,
      available: () => true,
    },
  };
}

class FakeSession {
  freed = false;
  locked = false;
  confirmed: boolean;
  pending: number | null = null;
  pendingPw: boolean = false;
  pendingCode: string | null = null;
  /** A prepared rotation: the new password tag (data key "rotates" with it). */
  rotating: number | null = null;
  passkey = false;
  committedPasskey = false;
  prfPending = false;
  committedPw: number;
  committedCode: string;
  rollbacks = 0;
  constructor(
    private rev: number,
    public pw: number,
    public code: string,
    confirmed = true,
  ) {
    this.confirmed = confirmed;
    this.committedPw = pw;
    this.committedCode = code;
    sessions.push(this);
  }
  static createProtected(_c: unknown, key: Uint8Array) {
    return new FakeSession(0, key[0], CODE, false);
  }
  static openWithPasswordKey(bytes: Uint8Array, key: Uint8Array) {
    if (bytes[3] !== 2) throw new Error('unsupported or unknown format: this is a demo vault without a password');
    if (key[0] !== bytes[4]) throw new Error('decryption failed: wrong key or corrupted data');
    return new FakeSession(bytes[1], bytes[4], bytes[5] === 1 ? CODE : bytes[5] === 2 ? ROT_CODE : OTHER_CODE);
  }
  static openWithPrf(bytes: Uint8Array, id: Uint8Array) {
    if (bytes[6] !== 1 || id.length !== 16) throw new Error('decryption failed: wrong key or corrupted data');
    const s = new FakeSession(bytes[1], bytes[4], bytes[5] === 1 ? CODE : bytes[5] === 2 ? ROT_CODE : OTHER_CODE);
    s.passkey = s.committedPasskey = true;
    return s;
  }
  static openWithRecovery(bytes: Uint8Array, code: string) {
    if (code !== CODE && code !== OTHER_CODE) throw new Error('validation failed: recovery code is not valid');
    if ((bytes[5] === 1 ? CODE : OTHER_CODE) !== code) throw new Error('decryption failed: wrong key or corrupted data');
    return new FakeSession(bytes[1], bytes[4], code);
  }
  get protected() {
    return true;
  }
  revision() {
    return this.rev;
  }
  list() {
    return '[]';
  }
  shownRecoveryCode() {
    if (!this.confirmed) return CODE;
    if (this.rotating !== null) return ROT_CODE;
    if (this.pendingCode) return this.pendingCode;
    throw new Error('validation failed: no recovery code to show');
  }
  confirmRecovery(code: string) {
    if (code !== this.code) throw new Error('validation failed: recovery code does not match');
    this.confirmed = true;
  }
  currentPasswordRequest() {
    return '{"cur":1}';
  }
  beginPasswordChange() {
    this.pendingPw = true;
    return '{"new":1}';
  }
  changePasswordWithKey(cur: Uint8Array, next: Uint8Array) {
    if (!this.pendingPw) throw new Error('validation failed: start the password change first');
    this.pendingPw = false;
    if (cur[0] !== this.pw) throw new Error('decryption failed: wrong key or corrupted data');
    this.pw = next[0];
  }
  changePasswordWithRecovery(code: string, next: Uint8Array) {
    if (!this.pendingPw) throw new Error('validation failed: start the password change first');
    this.pendingPw = false;
    if (code !== this.code) throw new Error('decryption failed: wrong key or corrupted data');
    this.pw = next[0];
  }
  beginRecoveryChange(cur: Uint8Array) {
    if (cur[0] !== this.pw) throw new Error('decryption failed: wrong key or corrupted data');
    this.pendingCode = OTHER_CODE;
  }
  finishRecoveryChange(code: string) {
    if (code !== this.pendingCode) throw new Error('validation failed: recovery code does not match');
    this.code = code;
    this.pendingCode = null;
  }
  cancelRecoveryChange() {
    this.pendingCode = null;
  }
  beginRotation(cur: Uint8Array, next: Uint8Array) {
    if (!this.pendingPw) throw new Error('validation failed: start the password change first');
    this.pendingPw = false;
    if (cur[0] !== this.pw) throw new Error('decryption failed: wrong key or corrupted data');
    this.pendingCode = null;
    this.rotating = next[0];
  }
  finishRotation(code: string) {
    if (this.rotating === null) throw new Error('validation failed: no key rotation in progress');
    if (code !== ROT_CODE) throw new Error('validation failed: recovery code does not match');
    this.pw = this.rotating;
    this.code = ROT_CODE;
    this.rotating = null;
  }
  cancelRotation() {
    this.rotating = null;
  }
  prfSlots() {
    return this.passkey ? JSON.stringify([PRF_SLOT]) : '[]';
  }
  beginPrfEnrolment(cur: Uint8Array) {
    if (cur[0] !== this.pw) throw new Error('decryption failed: wrong key or corrupted data');
    this.prfPending = true;
    return JSON.stringify({ slot_id: 'aaaaaaaaaaaaaaaa', salt: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA', vault_id: 'v'.repeat(32) });
  }
  finishPrfEnrolment(cur: Uint8Array, _id: Uint8Array, _rp: string, _be: boolean, _label: string, prf: Uint8Array) {
    if (!this.prfPending) throw new Error('validation failed: start the quick-unlock enrolment first');
    this.prfPending = false;
    if (cur[0] !== this.pw || prf.length !== 32) throw new Error('decryption failed');
    this.passkey = true;
  }
  cancelPrfEnrolment() {
    this.prfPending = false;
  }
  removePrfSlot(cur: Uint8Array) {
    if (cur[0] !== this.pw) throw new Error('decryption failed: wrong key or corrupted data');
    this.passkey = false;
  }
  beginRotationRevokingQuickUnlock(cur: Uint8Array, next: Uint8Array) {
    this.beginRotation(cur, next);
  }
  rollback() {
    this.rollbacks++;
    this.pw = this.committedPw;
    this.code = this.committedCode;
    this.passkey = this.committedPasskey;
  }
  sealProtected() {
    if (!this.confirmed) throw new Error('validation failed: confirm the recovery code before saving the vault');
    const revision = this.rev + 1;
    this.pending = revision;
    const b = v2(revision, this.pw, codeTag(this.code));
    return { bytes: this.passkey ? new Uint8Array([...b, 1]) : b, revision, free() {} };
  }
  commit(r: number) {
    if (r !== this.pending) throw new Error('no matching sealed revision');
    this.rev = r;
    this.committedPw = this.pw;
    this.committedCode = this.code;
    this.committedPasskey = this.passkey;
  }
  lock() {
    this.locked = true;
  }
  free() {
    this.freed = true;
  }
}

class FakeCreation {
  request() {
    return '{"create":1}';
  }
  free() {}
}

const fakeCore = {
  maxEnvelopeBytes: () => 1000,
  inspectEnvelope: (b: Uint8Array) => {
    if (b[0] !== 1) throw new Error('unsupported or unknown format: not a keymesh vault');
    return JSON.stringify({
      version: b[3] === 2 ? 2 : 1,
      vault_id: 'v',
      kek_id: b[3] === 2 ? null : 'synthetic-fixture-v1',
      revision: b[1],
    });
  },
  passwordRequest: () => '{"stored":1}',
  prfRequest: (b: Uint8Array) => (b[6] === 1 ? JSON.stringify([PRF_SLOT]) : '[]'),
  checkNewPassword: (pw: string) => {
    if ([...pw].length < 15) throw new Error('validation failed: password is too short');
  },
  ProtectedCreation: FakeCreation,
  VaultSession: FakeSession,
  DemoKeyProvider: {},
} as unknown as Core;

/** KDF whose results are released explicitly. */
class ManualKdf implements KdfRunner {
  calls: { password: string; request: string; d: ReturnType<typeof deferred<Uint8Array>> }[] = [];
  cancels = 0;
  /** If false, cancel() does not reject (simulates a result racing the lock). */
  rejectOnCancel = true;
  returned: Uint8Array[] = [];
  private startWaiters: { n: number; resolve: () => void }[] = [];
  derive(password: string, request: string): Promise<Uint8Array> {
    const d = deferred<Uint8Array>();
    this.calls.push({ password, request, d });
    for (const w of this.startWaiters.filter((x) => this.calls.length >= x.n)) w.resolve();
    return d.promise;
  }
  /**
   * START signal: resolves when the `n`th derivation has begun (its result is
   * still held). Fails the test after `ms` if it never starts, instead of
   * guessing how many turns the work before the KDF takes.
   */
  started(n = 1, ms = 2000): Promise<void> {
    if (this.calls.length >= n) return Promise.resolve();
    return new Promise<void>((resolve, reject) => {
      const w = { n, resolve: () => (clearTimeout(timer), resolve()) };
      const timer = setTimeout(() => {
        this.startWaiters = this.startWaiters.filter((x) => x !== w);
        reject(new Error(`KDF derivation ${n} did not start within ${ms} ms`));
      }, ms);
      this.startWaiters.push(w);
    });
  }
  release(i = this.calls.length - 1) {
    const c = this.calls[i];
    const key = keyFor(c.password);
    this.returned.push(key);
    c.d.resolve(key);
  }
  cancel() {
    this.cancels++;
    if (this.rejectOnCancel) for (const c of this.calls) c.d.reject(new KdfCancelledError());
  }
}

/** Store whose writes can be held before IndexedDB or made to fail. */
class TestStore extends VaultStore {
  gate: Promise<void> | null = null;
  fail = false;
  /** The write lands, then the call still reports an error (submitted-write uncertainty). */
  failAfterPut = false;
  /** Held after the write landed, before the call returns. */
  afterPut: Promise<void> | null = null;
  /** Reads fail (the outcome cannot be checked). */
  readFails = false;
  /** Writes whose transaction actually committed. */
  landed = 0;
  durabilities: (IDBTransactionDurability | undefined)[] = [];
  writes = 0;
  reads = 0;
  override async read(): Promise<StoredVault | null> {
    this.reads++;
    if (this.readFails) throw new Error('UnknownError (synthetic)');
    return super.read();
  }
  gateReached = false;
  override async compareAndSwap(
    expected: Uint8Array | null,
    next: StoredVault,
    guard?: () => void,
    durability?: IDBTransactionDurability,
  ): Promise<void> {
    this.durabilities.push(durability);
    if (this.gate) {
      this.gateReached = true;
      await this.gate;
    }
    if (this.fail) throw new Error('QuotaExceededError (synthetic)');
    this.writes++;
    await super.compareAndSwap(expected, next, guard, durability);
    this.landed++;
    if (this.afterPut) await this.afterPut;
    if (this.failAfterPut) throw new Error('UnknownError (synthetic, after put)');
  }
}

const rec = (bytes: Uint8Array): StoredVault => ({ bytes, vaultId: 'v', kekId: 'v2-key-slots', revision: bytes[1] });

function fileOf(bytes: Uint8Array, delay?: Promise<void>) {
  return {
    size: bytes.length,
    arrayBuffer: async () => {
      if (delay) await delay;
      return bytes.slice().buffer;
    },
  } as unknown as File;
}

async function stored(s: VaultStore): Promise<number[] | null> {
  const r = await s.read();
  return r ? Array.from(r.bytes) : null;
}

describe('VaultService password vault', () => {
  let prot: TestStore;
  let demo: TestStore;
  let kdf: ManualKdf;
  let vault: VaultService;

  function setup(secure = true) {
    sessions.length = 0;
    prot = new TestStore(new IDBFactory(), 'keymesh-vault');
    demo = new TestStore(new IDBFactory(), 'keymesh-demo');
    kdf = new ManualKdf();
    TestBed.configureTestingModule({
      providers: [
        { provide: VAULT_STORE, useValue: demo },
        { provide: PROTECTED_VAULT_STORE, useValue: prot },
        { provide: KDF_RUNNER, useValue: kdf },
        { provide: SECURE_CONTEXT, useValue: secure },
        { provide: CORE_LOADER, useValue: () => Promise.resolve(fakeCore) },
      ],
    });
    vault = TestBed.inject(VaultService);
  }

  /** A stored password vault (GOOD_PW / CODE), not unlocked. */
  async function withStored(revision = 3): Promise<Uint8Array> {
    const bytes = v2(revision);
    await prot.create(rec(bytes));
    await vault.init();
    expect(vault.protectedStored()?.version).toBe(2);
    prot.writes = 0;
    prot.landed = 0;
    return bytes;
  }

  async function unlocked(revision = 3): Promise<Uint8Array> {
    const bytes = await withStored(revision);
    const p = vault.unlockWithPassword(GOOD_PW);
    await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
    kdf.release();
    await p;
    expect(vault.status()).toBe('unlocked');
    expect(vault.isProtected()).toBe(true);
    // Count only derivations made by the code under test.
    kdf.calls = [];
    kdf.returned = [];
    return bytes;
  }

  describe('creation', () => {
    beforeEach(() => setup());

    it('stores nothing until the recovery code is confirmed; a wrong code keeps the pending vault', async () => {
      await vault.init();
      const p = vault.createProtected(GOOD_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      expect(kdf.calls[0].request).toBe('{"create":1}');
      kdf.release();
      await p;
      expect(vault.confirmingNewVault()).toBe(true);
      expect(vault.newVaultRecoveryCode()).toBe(CODE);
      expect(await stored(prot)).toBeNull();
      await expect(vault.confirmNewVault('WRONG')).rejects.toThrow(/does not match/);
      expect(vault.confirmingNewVault()).toBe(true);
      expect(await stored(prot)).toBeNull();
      await vault.confirmNewVault(CODE);
      expect(vault.status()).toBe('unlocked');
      expect(vault.keyMode()).toBe('protected');
      expect((await stored(prot))?.[3]).toBe(2);
      expect(kdf.returned[0].every((b) => b === 0)).toBe(true); // derived key zeroed
    });

    it('a weak password never reaches the KDF', async () => {
      await vault.init();
      await expect(vault.createProtected('short')).rejects.toThrow(/too short/);
      expect(kdf.calls.length).toBe(0);
    });

    it('lock during the KDF cancels it: no pending vault, nothing stored', async () => {
      await vault.init();
      const p = vault.createProtected(GOOD_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      vault.lock();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(kdf.cancels).toBe(1);
      expect(vault.confirmingNewVault()).toBe(false);
      expect(() => vault.newVaultRecoveryCode()).toThrow();
      expect(sessions.length).toBe(0);
      expect(await stored(prot)).toBeNull();
    });

    it('a KDF result that races the lock is zeroed and dropped', async () => {
      await vault.init();
      kdf.rejectOnCancel = false;
      const p = vault.createProtected(GOOD_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      vault.lock();
      kdf.release();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(kdf.returned[0].every((b) => b === 0)).toBe(true);
      expect(sessions.length).toBe(0);
      expect(vault.confirmingNewVault()).toBe(false);
    });

    it('lock while the confirmed vault is being written: never reported as success, nothing installed', async () => {
      await vault.init();
      const p = vault.createProtected(GOOD_PW);
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      await p;
      const hold = deferred();
      prot.gate = hold.promise;
      const c = vault.confirmNewVault(CODE);
      await until(() => prot.gateReached, 'write gate');
      vault.lock();
      prot.gate = null;
      hold.resolve();
      await expect(c).rejects.toBeInstanceOf(StaleWorkError);
      expect(vault.status()).not.toBe('unlocked');
      expect(await stored(prot)).toBeNull(); // cancelled before put
    });

    it('refuses when a password vault already exists (checked before the KDF)', async () => {
      await withStored();
      await expect(vault.createProtected(GOOD_PW)).rejects.toMatchObject({ code: 'protectedExists' });
      expect(kdf.calls.length).toBe(0);
    });
  });

  describe('unlock', () => {
    beforeEach(() => setup());

    it('wrong password is reported as such and leaves storage and state untouched', async () => {
      const bytes = await withStored();
      const p = vault.unlockWithPassword('synthetic wrong passphrase');
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      const e = await p.catch((x: unknown) => x);
      expect(e).toBeInstanceOf(VaultError);
      expect(errorKey(e)).toBe('errors.wrongPassword');
      expect(vault.status()).not.toBe('unlocked');
      expect(await stored(prot)).toEqual(Array.from(bytes));
      expect(kdf.returned[0].every((b) => b === 0)).toBe(true);
    });

    it('a second unlock while one runs is refused immediately (one KDF at a time)', async () => {
      await withStored();
      const a = vault.unlockWithPassword(GOOD_PW);
      const b = vault.unlockWithPassword(GOOD_PW);
      await expect(b).rejects.toMatchObject({ code: 'busy' });
      // The first unlock reads storage before its KDF; wait for its START, not a guessed number of turns.
      await kdf.started(1);
      expect(kdf.calls.length).toBe(1);
      expect(vault.credentialBusy()).toBe(true);
      kdf.release();
      await a;
      expect(kdf.calls.length).toBe(1);
      expect(vault.credentialBusy()).toBe(false);
      expect(vault.status()).toBe('unlocked');
    });

    it('lock during the unlock KDF: never unlocked afterwards (late result dropped)', async () => {
      await withStored();
      kdf.rejectOnCancel = false;
      const p = vault.unlockWithPassword(GOOD_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      vault.lock();
      kdf.release();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(vault.status()).not.toBe('unlocked');
      expect(sessions.length).toBe(0);
      expect(kdf.returned[0].every((b) => b === 0)).toBe(true);
    });

    it('lock during the storage read before the KDF: no KDF runs', async () => {
      const bytes = v2(3);
      await prot.create(rec(bytes));
      await vault.init();
      const p = vault.unlockWithPassword(GOOD_PW);
      vault.lock();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(kdf.calls.length).toBe(0);
    });

    it('lock clears a pending unlock; a fresh unlock afterwards still works', async () => {
      await withStored();
      const p = vault.unlockWithPassword(GOOD_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      vault.lock();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      const q = vault.unlockWithPassword(GOOD_PW);
      await until(() => kdf.calls.length > 1, 'second KDF call');
      kdf.release(1);
      await q;
      expect(vault.status()).toBe('unlocked');
    });
  });

  describe('insecure context (plain HTTP)', () => {
    beforeEach(() => setup(false));

    it('refuses every password-vault operation and never reads its database', async () => {
      await vault.init();
      expect(prot.reads).toBe(0);
      expect(vault.protectedStored()).toBeNull();
      for (const op of [
        () => vault.createProtected(GOOD_PW),
        () => vault.unlockWithPassword(GOOD_PW),
        () => vault.resetPassword(CODE, NEW_PW),
        () => vault.restoreProtected(fileOf(v2(1)), { password: GOOD_PW }),
        () => vault.restoreProtected(fileOf(v2(1)), { recoveryCode: CODE, newPassword: NEW_PW }),
        () => vault.confirmNewVault(CODE),
        () => vault.discardProtected(),
      ]) {
        await expect(op()).rejects.toMatchObject({ code: 'insecureContext' });
      }
      expect(kdf.calls.length).toBe(0);
      expect(prot.reads).toBe(0);
      expect(prot.writes).toBe(0);
    });
  });

  describe('reset and restore', () => {
    beforeEach(() => setup());

    it('reset with the recovery code rewraps under a new password with CAS', async () => {
      const bytes = await withStored();
      const p = vault.resetPassword(CODE, NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      expect(kdf.calls[0].password).toBe(NEW_PW);
      kdf.release();
      await p;
      const now = await stored(prot);
      expect(now?.[4]).toBe(2); // new password tag
      expect(now?.[1]).toBe(bytes[1] + 1);
      expect(vault.status()).toBe('unlocked');
    });

    it('wrong or invalid recovery code: refused before any KDF, storage untouched', async () => {
      const bytes = await withStored();
      const e = await vault.resetPassword(OTHER_CODE, NEW_PW).catch((x: unknown) => x);
      expect(errorKey(e)).toBe('errors.wrongRecovery');
      const f = await vault.resetPassword('NOT-A-CODE', NEW_PW).catch((x: unknown) => x);
      expect(errorKey(f)).toBe('errors.recoveryInvalid');
      expect(kdf.calls.length).toBe(0);
      expect(await stored(prot)).toEqual(Array.from(bytes));
    });

    it('a concurrent writer during reset wins; the reset is refused and nothing is installed', async () => {
      await withStored();
      const p = vault.resetPassword(CODE, NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      // Another tab replaces the vault while the KDF runs.
      const other = v2(9);
      const cur = (await prot.read())!.bytes;
      await prot.compareAndSwap(cur, rec(other));
      kdf.release();
      await expect(p).rejects.toBeInstanceOf(ConflictError);
      expect(vault.status()).not.toBe('unlocked');
      expect(await stored(prot)).toEqual(Array.from(other));
    });

    it('restore into empty storage with the backup password stores the exact bytes', async () => {
      await vault.init();
      const backup = v2(5);
      const p = vault.restoreProtected(fileOf(backup), { password: GOOD_PW });
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      await p;
      expect(await stored(prot)).toEqual(Array.from(backup));
      expect(vault.status()).toBe('unlocked');
    });

    it('restore with the recovery code sets a new password', async () => {
      await vault.init();
      const p = vault.restoreProtected(fileOf(v2(5)), { recoveryCode: CODE, newPassword: NEW_PW });
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      await p;
      expect((await stored(prot))?.[4]).toBe(2);
    });

    it('demo backups, garbage and oversize files are refused without a KDF or write', async () => {
      await vault.init();
      const demoBackup = new Uint8Array([1, 2, 3, 1]);
      await expect(vault.restoreProtected(fileOf(demoBackup), { password: GOOD_PW })).rejects.toMatchObject({ code: 'demoBackup' });
      await expect(vault.restoreProtected(fileOf(new Uint8Array([0xff, 1])), { password: GOOD_PW })).rejects.toMatchObject({
        code: 'backupRejected',
      });
      const big = { size: 5000, arrayBuffer: async () => new ArrayBuffer(5000) } as unknown as File;
      await expect(vault.restoreProtected(big, { password: GOOD_PW })).rejects.toMatchObject({ code: 'backupTooLarge' });
      expect(kdf.calls.length).toBe(0);
      expect(await stored(prot)).toBeNull();
    });

    it('wrong backup password: nothing written', async () => {
      await vault.init();
      const p = vault.restoreProtected(fileOf(v2(5)), { password: 'synthetic wrong passphrase' });
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      expect(errorKey(await p.catch((x: unknown) => x))).toBe('errors.wrongPassword');
      expect(await stored(prot)).toBeNull();
    });

    it('a stored but locked vault cannot be replaced by a restore', async () => {
      const bytes = await withStored();
      await expect(vault.restoreProtected(fileOf(v2(5)), { password: GOOD_PW })).rejects.toMatchObject({
        code: 'restoreNotAllowed',
      });
      expect(await stored(prot)).toEqual(Array.from(bytes));
    });

    it('lock during the backup file read cancels the restore before any KDF', async () => {
      await vault.init();
      const hold = deferred();
      let reading = false;
      const f = fileOf(v2(5), hold.promise);
      const read = f.arrayBuffer;
      f.arrayBuffer = () => {
        reading = true;
        return read();
      };
      const p = vault.restoreProtected(f, { password: GOOD_PW });
      await until(() => reading, 'file read');
      vault.lock();
      hold.resolve();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(kdf.calls.length).toBe(0);
      expect(await stored(prot)).toBeNull();
    });

    it('same-revision, different-content restore over the unlocked vault uses exact-byte CAS', async () => {
      await unlocked(3);
      // Another tab restored a sibling backup with the SAME revision.
      const cur = (await prot.read())!.bytes;
      const sibling = v2(3);
      await prot.compareAndSwap(cur, rec(sibling));
      const p = vault.restoreProtected(fileOf(v2(7)), { password: GOOD_PW });
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      await expect(p).rejects.toBeInstanceOf(ConflictError);
      expect(vault.status()).toBe('stale');
      expect(await stored(prot)).toEqual(Array.from(sibling));
    });
  });

  describe('changes while unlocked', () => {
    beforeEach(() => setup());

    it('change password: wrong current password is refused and nothing is written', async () => {
      const bytes = await unlocked();
      const p = vault.changePassword('synthetic wrong passphrase', NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      kdf.release(0);
      await until(() => kdf.calls.length > 1, 'KDF call');
      kdf.release(1);
      expect(errorKey(await p.catch((x: unknown) => x))).toBe('errors.wrongPassword');
      expect(prot.writes).toBe(0);
      expect(await stored(prot)).toEqual(Array.from(bytes));
    });

    it('change password: a failed write rolls the core back; storage keeps the old password', async () => {
      const bytes = await unlocked();
      prot.fail = true;
      const p = vault.changePassword(GOOD_PW, NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      kdf.release(0);
      await until(() => kdf.calls.length > 1, 'KDF call');
      kdf.release(1);
      await expect(p).rejects.toThrow(/synthetic/);
      const s = sessions[sessions.length - 1];
      expect(s.rollbacks).toBe(1);
      expect(s.pw).toBe(1);
      expect(await stored(prot)).toEqual(Array.from(bytes));
      expect(kdf.returned.every((k) => k.every((b) => b === 0))).toBe(true);
    });

    it('change password: lock between the two derivations cancels everything', async () => {
      const bytes = await unlocked();
      const p = vault.changePassword(GOOD_PW, NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      kdf.release(0);
      await until(() => kdf.calls.length > 1, 'second KDF call');
      vault.lock();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(await stored(prot)).toEqual(Array.from(bytes));
      expect(kdf.returned[0].every((b) => b === 0)).toBe(true);
    });

    it('change password succeeds and is persisted with CAS', async () => {
      const bytes = await unlocked();
      const p = vault.changePassword(GOOD_PW, NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      kdf.release(0);
      await until(() => kdf.calls.length > 1, 'KDF call');
      kdf.release(1);
      await p;
      const now = await stored(prot);
      expect(now?.[4]).toBe(2);
      expect(now).not.toEqual(Array.from(bytes));
      expect(vault.revision()).toBe(bytes[1] + 1);
    });

    it('new recovery code: needs the current password, then the code back', async () => {
      await unlocked();
      const bad = vault.beginRecoveryChange('synthetic wrong passphrase');
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      expect(errorKey(await bad.catch((x: unknown) => x))).toBe('errors.wrongPassword');
      const p = vault.beginRecoveryChange(GOOD_PW);
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      expect(await p).toBe(OTHER_CODE);
      await expect(vault.finishRecoveryChange(CODE)).rejects.toThrow(/does not match/);
      expect(prot.writes).toBe(0);
      await vault.finishRecoveryChange(OTHER_CODE);
      expect((await stored(prot))?.[5]).toBe(0);
    });

    it('delete removes only the exact vault this tab saw', async () => {
      await unlocked();
      const cur = (await prot.read())!.bytes;
      const other = v2(8);
      await prot.compareAndSwap(cur, rec(other));
      await expect(vault.discardProtected()).rejects.toBeInstanceOf(ConflictError);
      expect(await stored(prot)).toEqual(Array.from(other));
    });
  });
  describe('data-key rotation', () => {
    beforeEach(() => setup());

    /** Start a rotation GOOD_PW → NEW_PW and release both derivations. */
    async function begin(current = GOOD_PW, next = NEW_PW): Promise<string> {
      const p = vault.beginRotation(current, next);
      await kdf.started(1);
      kdf.release(0);
      await kdf.started(2);
      kdf.release(1);
      return p;
    }

    const session = () => sessions[sessions.length - 1];

    it('needs the current password and a NEW password; nothing changes before the code is back', async () => {
      const bytes = await unlocked();
      await expect(vault.beginRotation(GOOD_PW, GOOD_PW)).rejects.toMatchObject({ code: 'samePassword' });
      await expect(vault.beginRotation(GOOD_PW, 'short')).rejects.toThrow(/too short/);
      expect(kdf.calls).toHaveLength(0);
      const bad = vault.beginRotation('synthetic wrong passphrase', NEW_PW);
      await kdf.started(1);
      kdf.release(0);
      await kdf.started(2);
      kdf.release(1);
      expect(errorKey(await bad.catch((x: unknown) => x))).toBe('errors.wrongPassword');
      kdf.calls = [];
      kdf.returned = [];
      expect(await begin()).toBe(ROT_CODE);
      // Wrong code: refused, still pending, nothing written.
      await expect(vault.finishRotation(CODE)).rejects.toThrow(/does not match/);
      expect(session().rotating).toBe(2);
      expect(prot.writes).toBe(0);
      expect(await stored(prot)).toEqual(Array.from(bytes));
      expect(kdf.returned.every((k) => k.every((b) => b === 0))).toBe(true);
    });

    it('success: stored with exact-byte CAS and strict durability; new credentials only', async () => {
      const bytes = await unlocked();
      prot.durabilities = [];
      await begin();
      await vault.finishRotation(ROT_CODE);
      const now = await stored(prot);
      expect(now?.[4]).toBe(2); // new password
      expect(now?.[5]).toBe(2); // new recovery code
      expect(prot.durabilities).toEqual(['strict']);
      expect(vault.revision()).toBe(bytes[1] + 1);
      expect(vault.status()).toBe('unlocked');
      expect(session().rollbacks).toBe(0);
    });

    it('lock during a derivation cancels the rotation: nothing pending, nothing written', async () => {
      const bytes = await unlocked();
      const p = vault.beginRotation(GOOD_PW, NEW_PW);
      await kdf.started(1);
      kdf.release(0);
      await kdf.started(2);
      vault.lock();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(await stored(prot)).toEqual(Array.from(bytes));
      expect(kdf.returned[0].every((b) => b === 0)).toBe(true);
    });

    it('pre-commit failure (write refused before it lands): rolled back, old credentials stored', async () => {
      const bytes = await unlocked();
      await begin();
      prot.fail = true;
      await expect(vault.finishRotation(ROT_CODE)).rejects.toThrow(/synthetic/);
      expect(session().rollbacks).toBe(1);
      expect(session().pw).toBe(1);
      expect(await stored(prot)).toEqual(Array.from(bytes));
      expect(vault.status()).toBe('unlocked');
    });

    it('error AFTER the write landed: read back, the new bytes are there, so it counts as committed', async () => {
      const bytes = await unlocked();
      await begin();
      prot.failAfterPut = true;
      await vault.finishRotation(ROT_CODE);
      prot.failAfterPut = false;
      const now = await stored(prot);
      expect(now?.[4]).toBe(2);
      expect(session().rollbacks).toBe(0);
      expect(vault.revision()).toBe(bytes[1] + 1);
      expect(vault.status()).toBe('unlocked');
    });

    it('error after the write and the read-back fails too: uncertain, the vault is locked (nothing guessed)', async () => {
      await unlocked();
      await begin();
      prot.failAfterPut = true;
      prot.readFails = true;
      expect(errorKey(await vault.finishRotation(ROT_CODE).catch((x: unknown) => x))).toBe('errors.rotationUncertain');
      expect(vault.status()).not.toBe('unlocked');
      expect(vault.isProtected()).toBe(false);
      expect(session().rollbacks).toBe(0);
      prot.readFails = false;
      prot.failAfterPut = false;
      expect((await stored(prot))?.[4]).toBe(2); // it did land; the next unlock needs NEW_PW
    });

    it('another tab wrote first: CAS conflict, rolled back, stale; their bytes kept', async () => {
      await unlocked();
      await begin();
      const cur = (await prot.read())!.bytes;
      const other = v2(8);
      await prot.compareAndSwap(cur, rec(other));
      await expect(vault.finishRotation(ROT_CODE)).rejects.toBeInstanceOf(ConflictError);
      expect(vault.status()).toBe('stale');
      expect(session().rollbacks).toBe(1);
      expect(await stored(prot)).toEqual(Array.from(other));
    });

    it('lock while the write is held before IndexedDB: cancelled, nothing stored', async () => {
      const bytes = await unlocked();
      await begin();
      const gate = deferred();
      prot.gate = gate.promise;
      const p = vault.finishRotation(ROT_CODE);
      await until(() => prot.gateReached, 'write gate');
      vault.lock();
      gate.resolve();
      await expect(p).rejects.toBeInstanceOf(StaleWorkError);
      expect(await stored(prot)).toEqual(Array.from(bytes));
    });

    it('lock after the write landed: told the rotation was saved (no session resurrection)', async () => {
      await unlocked();
      await begin();
      const held = deferred();
      prot.afterPut = held.promise;
      const p = vault.finishRotation(ROT_CODE);
      await until(() => prot.landed === 1, 'write committed (completion held)');
      vault.lock();
      held.resolve();
      expect(errorKey(await p.catch((x: unknown) => x))).toBe('errors.rotatedWhileLocked');
      expect(vault.status()).not.toBe('unlocked');
      expect((await stored(prot))?.[4]).toBe(2);
      // Unlocking now needs the NEW password; the old one is refused.
      const bad = vault.unlockWithPassword(GOOD_PW);
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      expect(errorKey(await bad.catch((x: unknown) => x))).toBe('errors.wrongPassword');
      const good = vault.unlockWithPassword(NEW_PW);
      await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
      kdf.release();
      await good;
      expect(vault.status()).toBe('unlocked');
    });

    it('cancelling drops the pending rotation', async () => {
      const bytes = await unlocked();
      await begin();
      vault.cancelRotation();
      await expect(vault.finishRotation(ROT_CODE)).rejects.toThrow(/no key rotation/);
      expect(await stored(prot)).toEqual(Array.from(bytes));
    });
  });

  describe('stale reload keeps the password vault (never opens the demo)', () => {
    beforeEach(() => setup());

    async function staleAfterExternalChange(): Promise<Uint8Array> {
      await unlocked(3);
      const cur = (await prot.read())!.bytes;
      const external = v2(9);
      await prot.compareAndSwap(cur, rec(external));
      // A write from this tab now hits the CAS and marks it stale.
      const p = vault.changePassword(GOOD_PW, NEW_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      kdf.release(0);
      await until(() => kdf.calls.length > 1, 'second KDF call');
      kdf.release(1);
      await expect(p).rejects.toBeInstanceOf(ConflictError);
      expect(vault.status()).toBe('stale');
      kdf.calls = [];
      kdf.returned = [];
      return external;
    }

    it('with a demo vault stored: reload returns to password entry, demo untouched and not opened', async () => {
      const demoBytes = new Uint8Array([1, 4, 77, 1]);
      await demo.create({ bytes: demoBytes, vaultId: 'd', kekId: 'synthetic-fixture-v1', revision: 4 });
      const external = await staleAfterExternalChange();
      const opened = sessions.length;
      demo.writes = 0;
      prot.writes = 0;
      await vault.reload();
      expect(vault.status()).not.toBe('unlocked');
      expect(vault.keyMode()).not.toBe('synthetic-fixture');
      expect(vault.isProtected()).toBe(false);
      expect(sessions.length).toBe(opened); // nothing decrypted
      expect(vault.protectedStored()?.revision).toBe(external[1]);
      expect(await stored(demo)).toEqual(Array.from(demoBytes));
      expect(demo.writes).toBe(0);
      expect(prot.writes).toBe(0); // reload never writes
      // Unlocking now opens the CURRENT protected snapshot.
      const u = vault.unlockWithPassword(GOOD_PW);
      await until(() => kdf.calls.length > 0, 'KDF call');
      kdf.release(0);
      await u;
      expect(vault.keyMode()).toBe('protected');
      expect(vault.revision()).toBe(external[1]);
    });

    it('without a demo vault: reload succeeds and leaves the password vault locked', async () => {
      const external = await staleAfterExternalChange();
      prot.writes = 0;
      await expect(vault.reload()).resolves.toBeUndefined();
      expect(vault.status()).toBe('empty');
      expect(vault.protectedStored()?.revision).toBe(external[1]);
      expect(vault.protectedReloaded()).toBe(true);
      expect(prot.writes).toBe(0); // reload never writes
      expect(await demo.read()).toBeNull();
    });

    it('if the password vault was deleted elsewhere, reload shows no stored password vault', async () => {
      await unlocked(3);
      const cur = (await prot.read())!.bytes;
      await prot.compareAndClear(cur);
      await vault.reload();
      expect(vault.protectedStored()).toBeNull();
      expect(vault.status()).not.toBe('unlocked');
    });
  });
});

/**
 * Review fix (m5b P2): the real App is mounted. A rotation whose outcome is
 * only known after the vault locked must leave a visible, localized notice on
 * the LOCKED screen, after the Backup view (which started it) is destroyed.
 */
describe('rotation outcome notice in the mounted app', () => {
  let prot: TestStore;
  let kdf: ManualKdf;

  beforeAll(() => {
    // jsdom has no matchMedia (used by the theme and install button).
    globalThis.matchMedia ??= ((q: string) =>
      ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, onchange: null }) as unknown as MediaQueryList) as typeof matchMedia;
  });

  async function mountUnlocked() {
    sessions.length = 0;
    prot = new TestStore(new IDBFactory(), 'keymesh-vault');
    kdf = new ManualKdf();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideServiceWorker('ngsw-worker.js', { enabled: false }),
        { provide: VAULT_STORE, useValue: new TestStore(new IDBFactory(), 'keymesh-demo') },
        { provide: PROTECTED_VAULT_STORE, useValue: prot },
        { provide: KDF_RUNNER, useValue: kdf },
        { provide: SECURE_CONTEXT, useValue: true },
        { provide: CORE_LOADER, useValue: () => Promise.resolve(fakeCore) },
        { provide: PREFERENCE_STORAGE, useValue: null },
      ],
    });
    TestBed.inject(PreferencesService).setLocale('en');
    await prot.create(rec(v2(3)));
    prot.writes = 0;
    prot.landed = 0;
    const fixture = TestBed.createComponent(App);
    const el = fixture.nativeElement as HTMLElement;
    const settle = async () => {
      fixture.detectChanges();
      await fixture.whenStable();
      fixture.detectChanges();
    };
    const q = (id: string) => el.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    const type = (id: string, v: string) => {
      const input = q(id)!.querySelector('input') ?? (q(id) as HTMLInputElement);
      (input as HTMLInputElement).value = v;
      input.dispatchEvent(new Event('input'));
    };
    const vault = TestBed.inject(VaultService);
    await settle();
    await until(() => vault.status() !== 'loading' && vault.protectedStored() !== null, 'app started');
    await settle();
    type('unlock-password', GOOD_PW);
    await settle();
    q('unlock-protected')!.click();
    await kdf.started(1);
    kdf.release(0);
    await until(() => vault.status() === 'unlocked', 'unlock');
    await settle();
    kdf.calls = [];
    kdf.returned = [];
    // Backup view → rotation form → new code typed back.
    q('nav-backup')!.click();
    await settle();
    type('rotate-current', GOOD_PW);
    type('rotate-new', NEW_PW);
    type('rotate-confirm', NEW_PW);
    await settle();
    (q('begin-rotation')!.closest('form') as HTMLFormElement).dispatchEvent(new Event('submit'));
    await kdf.started(1);
    kdf.release(0);
    await kdf.started(2);
    kdf.release(1);
    await until(() => !!q('recovery-step'), 'new recovery code shown');
    await settle();
    (q('recovery-saved') as HTMLInputElement).click();
    await settle();
    type('recovery-confirm-input', ROT_CODE);
    await settle();
    return { fixture, el, q, settle, vault };
  }

  async function submitCode(q: (id: string) => HTMLElement | null) {
    (q('recovery-confirm')!.closest('form') as HTMLFormElement).dispatchEvent(new Event('submit'));
  }

  it('late committed write + lock: the locked screen says the NEW credentials are needed', async () => {
    const { fixture, el, q, settle, vault } = await mountUnlocked();
    const held = deferred();
    prot.afterPut = held.promise;
    await submitCode(q);
    await until(() => prot.landed === 1, 'write committed (completion still held)');
    q('lock')!.click(); // the user locks while the write is completing
    await settle();
    expect(el.querySelector('km-backup')).toBeNull(); // the view that started it is gone
    held.resolve();
    await until(() => (fixture.detectChanges(), !!q('credential-notice')), 'notice rendered on the locked screen');
    await settle();
    const notice = q('credential-notice');
    expect(notice).not.toBeNull();
    expect(notice!.getAttribute('data-code')).toBe('rotatedWhileLocked');
    expect(notice!.textContent).toContain(en['notice.rotatedWhileLocked']);
    expect(q('unlock-password')).not.toBeNull(); // still the locked screen
    // Acknowledged: gone.
    q('credential-notice-ack')!.click();
    await settle();
    expect(q('credential-notice')).toBeNull();
  });

  it('uncertain outcome: the vault is locked and the locked screen explains how to reconcile (zh-TW)', async () => {
    const { fixture, el, q, settle, vault } = await mountUnlocked();
    TestBed.inject(PreferencesService).setLocale('zh-TW');
    prot.failAfterPut = true;
    prot.readFails = true;
    await submitCode(q);
    await until(() => (fixture.detectChanges(), !!q('credential-notice')), 'notice rendered on the locked screen');
    prot.failAfterPut = false;
    prot.readFails = false;
    await settle();
    expect(vault.status()).not.toBe('unlocked');
    expect(el.querySelector('km-backup')).toBeNull();
    const notice = q('credential-notice');
    expect(notice?.getAttribute('data-code')).toBe('rotationUncertain');
    expect(notice!.textContent).toContain(zhTW['notice.rotationUncertain']);
    // A successful unlock (with whichever credential works) resolves it.
    const p = vault.unlockWithPassword(NEW_PW);
    await until(() => kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length, 'KDF call');
    kdf.release();
    await p;
    await settle();
    expect(vault.credentialNotice()).toBeNull();
  });

  it('an older operation never overwrites a newer notice', async () => {
    TestBed.resetTestingModule();
    const { vault } = await mountUnlocked();
    const older = vault.credentialOpSeq();
    vault.recordNotice('rotationUncertain', older + 1);
    vault.recordNotice('rotatedWhileLocked', older);
    expect(vault.credentialNotice()?.code).toBe('rotationUncertain');
  });
});

/**
 * Passkey enrolment outcomes in the mounted app (C1 gate response). The
 * notice must be visible on the LOCKED screen after the Backup view is gone;
 * "orphan" only when it is proven nothing was written; an unknown outcome
 * stays pending through failed unlocks and is reconciled by the next
 * successful one.
 */
describe('passkey enrolment outcomes in the mounted app', () => {
  let prot: TestStore;
  let kdf: ManualKdf;

  beforeAll(() => {
    globalThis.matchMedia ??= ((q: string) =>
      ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, onchange: null }) as unknown as MediaQueryList) as typeof matchMedia;
  });

  let mono = 1_000;
  let wall = 1_800_000_000_000;
  const clock = { mono: () => mono, wall: () => wall };
  /** Past the 5-minute idle deadline, with no input and no timer. */
  const expire = () => {
    mono += 301_000;
    wall += 301_000;
  };

  async function mount(wa: ReturnType<typeof fakeWebAuthn>) {
    sessions.length = 0;
    prot = new TestStore(new IDBFactory(), 'keymesh-vault');
    kdf = new ManualKdf();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideServiceWorker('ngsw-worker.js', { enabled: false }),
        { provide: VAULT_STORE, useValue: new TestStore(new IDBFactory(), 'keymesh-demo') },
        { provide: PROTECTED_VAULT_STORE, useValue: prot },
        { provide: KDF_RUNNER, useValue: kdf },
        { provide: SECURE_CONTEXT, useValue: true },
        { provide: CORE_LOADER, useValue: () => Promise.resolve(fakeCore) },
        { provide: PREFERENCE_STORAGE, useValue: null },
        { provide: WEBAUTHN, useValue: wa.port },
        { provide: LOCK_CLOCK, useValue: clock },
        { provide: COARSE_POINTER, useValue: false },
        { provide: AUTOLOCK_STORAGE, useValue: null },
      ],
    });
    TestBed.inject(PreferencesService).setLocale('en');
    await prot.create(rec(v2(3)));
    prot.writes = 0;
    prot.landed = 0;
    const fixture = TestBed.createComponent(App);
    const el = fixture.nativeElement as HTMLElement;
    const settle = async () => {
      fixture.detectChanges();
      await fixture.whenStable();
      fixture.detectChanges();
    };
    const q = (id: string) => el.querySelector<HTMLElement>(`[data-testid="${id}"]`);
    const vault = TestBed.inject(VaultService);
    await settle();
    await until(() => vault.status() !== 'loading' && vault.protectedStored() !== null, 'app started');
    const unlock = async (pw: string) => {
      let settled = false;
      const p = vault
        .unlockWithPassword(pw)
        .catch(() => undefined) // handled at once (a failed unlock is expected here)
        .finally(() => (settled = true));
      // With storage reads failing the unlock fails before any KDF runs.
      await until(() => settled || (kdf.calls.length > 0 && kdf.returned.length < kdf.calls.length), 'KDF call or failure');
      if (!settled) kdf.release();
      await p;
      kdf.calls = [];
      kdf.returned = [];
      await settle();
    };
    await unlock(GOOD_PW);
    expect(vault.status()).toBe('unlocked');
    return { fixture, el, q, settle, vault, unlock };
  }

  async function enrol(vault: VaultService) {
    const p = vault.enrollQuickUnlock(GOOD_PW, 'Synthetic key');
    await kdf.started(1);
    kdf.release(0);
    return p;
  }

  const shown = (q: (id: string) => HTMLElement | null) => ({
    code: q('credential-notice')?.getAttribute('data-code') ?? null,
    text: q('credential-notice')?.textContent ?? '',
  });

  it('success: stored, no notice', async () => {
    const wa = fakeWebAuthn();
    const { vault, q, settle } = await mount(wa);
    await enrol(vault);
    await settle();
    expect(Array.from((await prot.read())!.bytes)[6]).toBe(1);
    expect(q('credential-notice')).toBeNull();
  });

  it('wrong master password: refused before create(), no passkey, no notice', async () => {
    const wa = fakeWebAuthn();
    const { vault, q, settle } = await mount(wa);
    const p = vault.enrollQuickUnlock('synthetic wrong passphrase', 'x');
    await kdf.started(1);
    kdf.release(0);
    expect(errorKey(await p.catch((e: unknown) => e))).toBe('errors.wrongPassword');
    expect(wa.calls.create).toBe(0);
    await settle();
    expect(q('credential-notice')).toBeNull();
  });

  it('authenticator without PRF: orphan guidance (label, time) survives the lock; password fallback works', async () => {
    const wa = fakeWebAuthn({ prf: false });
    const { vault, q, settle, unlock } = await mount(wa);
    expect(errorKey(await enrol(vault).catch((e: unknown) => e))).toBe('errors.quickUnlockOrphan');
    expect(prot.writes).toBe(0);
    vault.lock();
    await settle();
    expect(shown(q).code).toBe('quickUnlockOrphan');
    expect(shown(q).text).toContain(en['notice.quickUnlockOrphan']);
    expect(q('credential-notice-passkey')?.textContent).toContain('Synthetic key');
    await unlock(GOOD_PW); // password still works; the orphan note stays until acknowledged
    expect(vault.status()).toBe('unlocked');
    expect(shown(q).code).toBe('quickUnlockOrphan');
  });

  it('lock during create(): the ceremony is aborted; the may-exist passkey gets the guidance; nothing written', async () => {
    const hold = deferred();
    const wa = fakeWebAuthn({ hold: hold.promise });
    const { vault, q, settle } = await mount(wa);
    const p = enrol(vault);
    await until(() => wa.calls.create === 1, 'create() started');
    vault.lock();
    hold.resolve();
    await p.catch(() => undefined);
    await settle();
    expect(prot.writes).toBe(0);
    expect(shown(q).code).toBe('quickUnlockOrphan');
    expect(vault.status()).not.toBe('unlocked');
  });

  it('write outcome unknown: pending (no delete advice) through a failed unlock; reconciled as ADDED when the write had landed', async () => {
    const wa = fakeWebAuthn();
    const { vault, q, settle, unlock } = await mount(wa);
    prot.failAfterPut = true;
    prot.readFails = true;
    expect(errorKey(await enrol(vault).catch((e: unknown) => e))).toBe('errors.quickUnlockUncertain');
    await settle();
    expect(vault.status()).not.toBe('unlocked');
    expect(shown(q).code).toBe('quickUnlockUncertain');
    expect(shown(q).text).not.toContain(en['notice.quickUnlockOrphan']);
    // Reads still failing: the unlock fails; the pending notice stays.
    await unlock(GOOD_PW);
    expect(vault.status()).not.toBe('unlocked');
    expect(shown(q).code).toBe('quickUnlockUncertain');
    // A wrong password: still pending.
    prot.readFails = false;
    prot.failAfterPut = false;
    await unlock('synthetic wrong passphrase');
    expect(shown(q).code).toBe('quickUnlockUncertain');
    // Successful unlock: the stored vault HAS the passkey → no orphan.
    await unlock(GOOD_PW);
    expect(vault.status()).toBe('unlocked');
    expect(q('credential-notice')).toBeNull();
  });

  it('write outcome unknown and the write had NOT landed: reconciled as an orphan only after a successful unlock', async () => {
    const wa = fakeWebAuthn();
    const { vault, q, settle, unlock } = await mount(wa);
    prot.fail = true; // the write never lands...
    prot.readFails = true; // ...and the outcome can't be read back
    // A write error that is neither a conflict nor a guard stop goes to the
    // read-back; with reads failing the outcome is unknown.
    const r = await enrol(vault).catch((e: unknown) => e);
    expect(errorKey(r)).toBe('errors.quickUnlockUncertain');
    await settle();
    expect(shown(q).code).toBe('quickUnlockUncertain');
    prot.fail = false;
    prot.readFails = false;
    await unlock(GOOD_PW);
    expect(vault.status()).toBe('unlocked');
    expect(shown(q).code).toBe('quickUnlockOrphan'); // proven absent now
  });
});

/**
 * Review fix (m5c P2): elapsed idle deadlines are checked on every async
 * continuation of a credential operation (real AutoLock, injected clock, no
 * timers run). Each case: the deadline passes while the operation waits;
 * when it resumes, the vault locks and nothing new is written.
 */
describe('deadlines on async continuations (mounted app, real auto-lock)', () => {
  // Reuses the passkey describe's helpers through a fresh mount.
  let prot: TestStore;
  let kdf: ManualKdf;
  let mono = 1_000;
  let wall = 1_800_000_000_000;
  const clock = { mono: () => mono, wall: () => wall };
  const expire = (ms = 301_000) => {
    mono += ms;
    wall += ms;
  };

  beforeAll(() => {
    globalThis.matchMedia ??= ((q: string) =>
      ({ matches: false, media: q, addEventListener() {}, removeEventListener() {}, onchange: null }) as unknown as MediaQueryList) as typeof matchMedia;
  });

  async function mount(wa: ReturnType<typeof fakeWebAuthn>, withPasskey = false) {
    sessions.length = 0;
    prot = new TestStore(new IDBFactory(), 'keymesh-vault');
    kdf = new ManualKdf();
    TestBed.resetTestingModule();
    TestBed.configureTestingModule({
      providers: [
        provideServiceWorker('ngsw-worker.js', { enabled: false }),
        { provide: VAULT_STORE, useValue: new TestStore(new IDBFactory(), 'keymesh-demo') },
        { provide: PROTECTED_VAULT_STORE, useValue: prot },
        { provide: KDF_RUNNER, useValue: kdf },
        { provide: SECURE_CONTEXT, useValue: true },
        { provide: CORE_LOADER, useValue: () => Promise.resolve(fakeCore) },
        { provide: PREFERENCE_STORAGE, useValue: null },
        { provide: WEBAUTHN, useValue: wa.port },
        { provide: LOCK_CLOCK, useValue: clock },
        { provide: COARSE_POINTER, useValue: false },
        { provide: AUTOLOCK_STORAGE, useValue: null },
      ],
    });
    const b = v2(3);
    await prot.create(rec(withPasskey ? new Uint8Array([...b, 1]) : b));
    prot.writes = 0;
    prot.landed = 0;
    const fixture = TestBed.createComponent(App);
    const vault = TestBed.inject(VaultService);
    fixture.detectChanges();
    await until(() => vault.status() !== 'loading' && vault.protectedStored() !== null, 'app started');
    const p = vault.unlockWithPassword(GOOD_PW);
    await kdf.started(1);
    kdf.release(0);
    await p;
    kdf.calls = [];
    kdf.returned = [];
    expect(vault.status()).toBe('unlocked');
    const before = Array.from((await prot.read())!.bytes);
    return { vault, before };
  }

  const lockedByIdle = async (vault: VaultService, before: number[]) => {
    expect(vault.status()).not.toBe('unlocked');
    expect(TestBed.inject(AutoLock).lastReason()).toBe('idle');
    expect(prot.landed).toBe(0);
    expect(Array.from((await prot.read())!.bytes)).toEqual(before);
  };

  it('enrolment: deadline passes during the KDF → no ceremony, no write, locked', async () => {
    const wa = fakeWebAuthn();
    const { vault, before } = await mount(wa);
    const p = vault.enrollQuickUnlock(GOOD_PW, 'k');
    await kdf.started(1);
    expire();
    kdf.release(0);
    await expect(p).rejects.toBeInstanceOf(StaleWorkError);
    expect(wa.calls.create).toBe(0);
    await lockedByIdle(vault, before);
    expect(kdf.returned[0].every((b) => b === 0)).toBe(true); // derived key zeroed
  });

  it('enrolment: deadline passes during create() → the late credential is dropped (orphan guidance), no write, locked', async () => {
    const hold = deferred();
    const wa = fakeWebAuthn({ hold: hold.promise });
    const { vault, before } = await mount(wa);
    const p = vault.enrollQuickUnlock(GOOD_PW, 'k');
    await kdf.started(1);
    kdf.release(0);
    await until(() => wa.calls.create === 1, 'create() started');
    expire();
    hold.resolve();
    await p.catch(() => undefined);
    await lockedByIdle(vault, before);
    expect(vault.credentialNotice()?.code).toBe('quickUnlockOrphan');
  });

  it('enrolment: deadline passes right before the write → the store guard stops put', async () => {
    const wa = fakeWebAuthn();
    const { vault, before } = await mount(wa);
    const gate = deferred();
    prot.gate = gate.promise;
    const p = vault.enrollQuickUnlock(GOOD_PW, 'k');
    await kdf.started(1);
    kdf.release(0);
    await until(() => prot.gateReached, 'write about to be issued');
    expire();
    gate.resolve();
    await p.catch(() => undefined);
    await lockedByIdle(vault, before);
  });

  it('removal: deadline passes during the KDF → nothing removed, locked', async () => {
    const wa = fakeWebAuthn();
    const { vault, before } = await mount(wa, true);
    const p = vault.removeQuickUnlock(GOOD_PW, 'aaaaaaaaaaaaaaaa');
    await kdf.started(1);
    expire();
    kdf.release(0);
    await expect(p).rejects.toBeInstanceOf(StaleWorkError);
    await lockedByIdle(vault, before);
  });

  it('password change: deadline passes during the second KDF → nothing written, locked', async () => {
    const wa = fakeWebAuthn();
    const { vault, before } = await mount(wa);
    const p = vault.changePassword(GOOD_PW, NEW_PW);
    await kdf.started(1);
    kdf.release(0);
    await kdf.started(2);
    expire();
    kdf.release(1);
    await expect(p).rejects.toBeInstanceOf(StaleWorkError);
    await lockedByIdle(vault, before);
  });

  it('a protected read after expiry locks first (no lifecycle event needed)', async () => {
    const wa = fakeWebAuthn();
    const { vault } = await mount(wa);
    expire();
    expect(() => vault.quickUnlockSlots()).toThrow();
    expect(vault.status()).not.toBe('unlocked');
  });

  it('locked start: quick unlock has no idle deadline (hours later it still opens)', async () => {
    const wa = fakeWebAuthn();
    const { vault } = await mount(wa, true);
    vault.lock();
    expire(3 * 3600_000);
    await vault.unlockWithQuickUnlock();
    expect(vault.status()).toBe('unlocked');
    expect(wa.calls.get).toBe(1);
    // And the new session starts with fresh deadlines.
    expect(() => vault.quickUnlockSlots()).not.toThrow();
  });
});
