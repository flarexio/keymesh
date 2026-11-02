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

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  let reject!: (e: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

const flush = async () => {
  for (let i = 0; i < 20; i++) await Promise.resolve();
  await new Promise((r) => setTimeout(r, 0));
};

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

/** v2 envelope stand-in: [1, revision, uniqueness, 2, passwordTag, codeTag]. */
let counter = 0;
const v2 = (revision: number, pw = 1, code = 1) => new Uint8Array([1, revision, ++counter % 256, 2, pw, code]);
const pwTag = (pw: string) => (pw === GOOD_PW ? 1 : pw === NEW_PW ? 2 : 9);

/** The fake "derived key": byte 0 tags which password it came from. */
const keyFor = (pw: string) => new Uint8Array([pwTag(pw), 0, 0, 0]);

const sessions: FakeSession[] = [];

class FakeSession {
  freed = false;
  locked = false;
  confirmed: boolean;
  pending: number | null = null;
  pendingPw: boolean = false;
  pendingCode: string | null = null;
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
    return new FakeSession(bytes[1], bytes[4], bytes[5] === 1 ? CODE : OTHER_CODE);
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
  rollback() {
    this.rollbacks++;
    this.pw = this.committedPw;
    this.code = this.committedCode;
  }
  sealProtected() {
    if (!this.confirmed) throw new Error('validation failed: confirm the recovery code before saving the vault');
    const revision = this.rev + 1;
    this.pending = revision;
    return { bytes: v2(revision, this.pw, this.code === CODE ? 1 : 0), revision, free() {} };
  }
  commit(r: number) {
    if (r !== this.pending) throw new Error('no matching sealed revision');
    this.rev = r;
    this.committedPw = this.pw;
    this.committedCode = this.code;
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
  derive(password: string, request: string): Promise<Uint8Array> {
    const d = deferred<Uint8Array>();
    this.calls.push({ password, request, d });
    return d.promise;
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
  writes = 0;
  reads = 0;
  override async read(): Promise<StoredVault | null> {
    this.reads++;
    return super.read();
  }
  gateReached = false;
  override async compareAndSwap(expected: Uint8Array | null, next: StoredVault, guard?: () => void): Promise<void> {
    if (this.gate) {
      this.gateReached = true;
      await this.gate;
    }
    if (this.fail) throw new Error('QuotaExceededError (synthetic)');
    this.writes++;
    await super.compareAndSwap(expected, next, guard);
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
      await flush();
      expect(kdf.calls.length).toBe(1);
      expect(vault.credentialBusy()).toBe(true);
      kdf.release();
      await a;
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
});
