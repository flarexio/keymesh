/**
 * Deterministic orchestration tests for VaultService: a fake core and a store
 * whose writes can be held open, so lock/restore/write interleavings are
 * exact. (Real crypto is covered by Rust tests and the browser E2E.)
 */
import { TestBed } from '@angular/core/testing';
import { IDBFactory } from 'fake-indexeddb';
import { CORE_LOADER, LockedError, StaleWorkError, VAULT_STORE, VaultService } from './vault.service';
import { errorKey } from './errors';
import { PASSWORD_PRESETS } from './password-options';
import { ConflictError, StoredVault, VaultStore } from './vault-store';
import { FIXTURE_KEY_ID } from './types';
import type { Core } from './wasm';

function deferred<T = void>() {
  let resolve!: (v: T) => void;
  const promise = new Promise<T>((r) => (resolve = r));
  return { promise, resolve };
}

/** Envelope stand-in: [validity, revision, uniqueness]. 0xFF = undecryptable. */
let counter = 0;
const env = (revision: number, valid = true) =>
  new Uint8Array([valid ? 1 : 0xff, revision, ++counter % 256]);

class FakeKey {
  freed = false;
  constructor(readonly mode: string) {}
  get keyId() {
    return FIXTURE_KEY_ID;
  }
  free() {
    this.freed = true;
  }
}

const sessions: FakeSession[] = [];

class FakeSession {
  freed = false;
  locked = false;
  items: string[] = [];
  pending: number | null = null;
  constructor(private rev: number) {
    sessions.push(this);
  }
  static create() {
    return new FakeSession(0);
  }
  static open(bytes: Uint8Array) {
    if (bytes[0] !== 1) throw new Error('decryption failed: wrong key or corrupted data');
    return new FakeSession(bytes[1]);
  }
  revision() {
    return this.rev;
  }
  list() {
    return JSON.stringify(this.items.map((t) => ({ id: t, kind: 'secure_note', title: t, subtitle: null, tags: [] })));
  }
  /** Mirrors the core's preview slots: exact match, consumed on save. */
  previews: Record<string, string> = {};
  savePreviewCalls = 0;
  previewPassword() {
    return (this.previews['password'] = `pv-${++counter}`);
  }
  savePreview(kind: string, shown: string, title: string) {
    this.savePreviewCalls++;
    if (this.previews[kind] !== shown) throw new Error('validation failed: generated value is no longer available');
    delete this.previews[kind];
    this.items.push(title);
    return title;
  }
  discardPreviews() {
    this.previews = {};
  }
  createItem(json: string) {
    const t = (JSON.parse(json) as { title: string }).title;
    this.items.push(t);
    return t;
  }
  seal() {
    const revision = this.rev + 1;
    this.pending = revision;
    return { bytes: env(revision), revision, free() {} };
  }
  commit(r: number) {
    if (r !== this.pending) throw new Error('no matching sealed revision');
    this.rev = r;
  }
  lock() {
    this.locked = true;
  }
  free() {
    this.freed = true;
  }
}

const fakeCore = {
  maxEnvelopeBytes: () => 1000,
  inspectEnvelope: (b: Uint8Array) =>
    JSON.stringify({ vault_id: 'v1', kek_id: FIXTURE_KEY_ID, revision: b[1] }),
  DemoKeyProvider: {
    ephemeral: () => new FakeKey('ephemeral'),
    syntheticFixture: () => new FakeKey('synthetic-fixture'),
  },
  VaultSession: FakeSession,
  generatePassword: () => 'x',
} as unknown as Core;

/** Store whose compareAndSwap can be paused before it reaches IndexedDB. */
class GatedStore extends VaultStore {
  gate: Promise<void> | null = null;
  writes = 0;
  override async compareAndSwap(expected: Uint8Array | null, next: StoredVault): Promise<void> {
    if (this.gate) await this.gate;
    this.writes++;
    return super.compareAndSwap(expected, next);
  }
}

function fileOf(bytes: Uint8Array, delay?: Promise<void>) {
  let reads = 0;
  const f = {
    size: bytes.length,
    arrayBuffer: async () => {
      reads++;
      if (delay) await delay;
      return bytes.slice().buffer;
    },
  };
  return { file: f as unknown as File, reads: () => reads };
}

describe('VaultService lock / restore / concurrency', () => {
  let store: GatedStore;
  let vault: VaultService;

  async function unlockedWith(revision: number): Promise<Uint8Array> {
    const bytes = env(revision);
    await store.create({ bytes, vaultId: 'v1', kekId: FIXTURE_KEY_ID, revision });
    await vault.init();
    expect(vault.status()).toBe('stored');
    await vault.openStored();
    expect(vault.status()).toBe('unlocked');
    store.writes = 0; // count only writes made by the code under test
    return bytes;
  }

  beforeEach(() => {
    sessions.length = 0;
    store = new GatedStore(new IDBFactory());
    TestBed.configureTestingModule({
      providers: [
        { provide: VAULT_STORE, useValue: store },
        { provide: CORE_LOADER, useValue: () => Promise.resolve(fakeCore) },
      ],
    });
    vault = TestBed.inject(VaultService);
  });

  it('lock during a delayed file read cancels the restore; nothing is opened or written', async () => {
    const original = await unlockedWith(3);
    const hold = deferred();
    const { file, reads } = fileOf(env(7), hold.promise);
    const restore = vault.restore(file);
    await Promise.resolve();
    await Promise.resolve();
    expect(reads()).toBe(1);
    vault.lock();
    const opened = sessions.length;
    hold.resolve();
    await expect(restore).rejects.toBeInstanceOf(StaleWorkError);
    expect(vault.status()).toBe('locked');
    expect(sessions.length).toBe(opened); // backup never decrypted
    expect(store.writes).toBe(0);
    expect(Array.from((await store.read())!.bytes)).toEqual(Array.from(original));
  });

  it('lock during a delayed storage write wins: nothing is installed, candidate freed', async () => {
    await unlockedWith(3);
    const hold = deferred();
    store.gate = hold.promise;
    const backup = env(7);
    const restore = vault.restore(fileOf(backup).file);
    // Let the restore reach the gated write.
    for (let i = 0; i < 10 && sessions.length < 2; i++) await Promise.resolve();
    await new Promise((r) => setTimeout(r, 0));
    const candidate = sessions[sessions.length - 1];
    vault.lock();
    store.gate = null;
    hold.resolve();
    await expect(restore).rejects.toBeInstanceOf(StaleWorkError);
    expect(vault.status()).toBe('locked');
    expect(vault.items()).toEqual([]);
    expect(candidate.freed).toBe(true);
    // The verified backup was persisted; unlocking reads it (no plaintext
    // was repopulated by the cancelled operation itself).
    expect(Array.from((await store.read())!.bytes)).toEqual(Array.from(backup));
    await vault.openStored();
    expect(vault.revision()).toBe(7);
  });

  it('a restore queued before a lock never starts', async () => {
    await unlockedWith(3);
    const hold = deferred();
    store.gate = hold.promise;
    const mutation = vault.createItem({
      title: 'slow',
      tags: [],
      notes: null,
      custom_fields: [],
      data: { kind: 'secure_note', body: 'x' },
    });
    // Wait until the mutation is in flight, blocked at the gated write.
    const session = sessions[sessions.length - 1];
    for (let i = 0; i < 50 && session.pending === null; i++) await new Promise((r) => setTimeout(r, 0));
    expect(session.pending).toBe(4);
    const { file, reads } = fileOf(env(9));
    const restore = vault.restore(file);
    vault.lock();
    store.gate = null;
    hold.resolve();
    await expect(mutation).rejects.toBeInstanceOf(StaleWorkError);
    await expect(restore).rejects.toBeInstanceOf(StaleWorkError);
    expect(reads()).toBe(0);
    expect(vault.status()).toBe('locked');
    expect((await store.read())!.revision).toBe(4); // only the slow mutation's write landed
  });

  it('a stale tab cannot restore, and storage is untouched', async () => {
    await unlockedWith(3);
    vault.status.set('stale');
    await expect(vault.restore(fileOf(env(7)).file)).rejects.toBeInstanceOf(ConflictError);
    expect(store.writes).toBe(0);
    expect((await store.read())!.revision).toBe(3);
  });

  it('a concurrent writer during restore wins; restore is rejected and the tab goes stale', async () => {
    const original = await unlockedWith(3);
    const hold = deferred();
    const restore = vault.restore(fileOf(env(7), hold.promise).file);
    await Promise.resolve();
    // Another tab writes meanwhile (exact-snapshot CAS on its own view).
    const other = env(4);
    await store.compareAndSwap(original, { bytes: other, vaultId: 'v1', kekId: FIXTURE_KEY_ID, revision: 4 });
    hold.resolve();
    await expect(restore).rejects.toBeInstanceOf(ConflictError);
    expect(vault.status()).toBe('stale');
    expect(Array.from((await store.read())!.bytes)).toEqual(Array.from(other));
  });

  it('wrong/corrupt backup is rejected without writing', async () => {
    await unlockedWith(3);
    await expect(vault.restore(fileOf(env(7, false)).file)).rejects.toThrow('Backup rejected');
    expect(store.writes).toBe(0);
    expect(vault.status()).toBe('unlocked');
  });

  it('valid same-tab restore installs the backup', async () => {
    await unlockedWith(3);
    await vault.restore(fileOf(env(2)).file);
    expect(vault.status()).toBe('unlocked');
    expect(vault.revision()).toBe(2);
  });

  it('initial restore into empty storage, but not over a vault that appeared meanwhile', async () => {
    await vault.init();
    expect(vault.status()).toBe('empty');
    const hold = deferred();
    const restore = vault.restore(fileOf(env(5), hold.promise).file);
    await Promise.resolve();
    await store.create({ bytes: env(1), vaultId: 'v1', kekId: FIXTURE_KEY_ID, revision: 1 });
    hold.resolve();
    await expect(restore).rejects.toBeInstanceOf(ConflictError);
    expect((await store.read())!.revision).toBe(1);

    await store.clear();
    await vault.restore(fileOf(env(5)).file);
    expect(vault.status()).toBe('unlocked');
    expect(vault.revision()).toBe(5);
  });

  it('lock during a delayed unlock read keeps the vault locked', async () => {
    await unlockedWith(3);
    vault.lock();
    const hold = deferred();
    const read = store.read.bind(store);
    store.read = async () => {
      await hold.promise;
      return read();
    };
    const open = vault.openStored();
    vault.lock();
    hold.resolve();
    await expect(open).rejects.toBeInstanceOf(StaleWorkError);
    expect(vault.status()).toBe('locked');
  });
  describe('saving a generated preview', () => {
    it('stores exactly the shown value once; a duplicate save is refused and writes nothing', async () => {
      await unlockedWith(3);
      const shown = vault.previewPassword(PASSWORD_PRESETS.default);
      await expect(vault.savePreview('password', shown, 'gen')).resolves.toBe('gen');
      expect(store.writes).toBe(1);
      expect(vault.revision()).toBe(4);
      const dup = vault.savePreview('password', shown, 'gen');
      await expect(dup).rejects.toThrow(/no longer available/);
      expect(errorKey(await dup.catch((e) => e))).toBe('errors.previewGone');
      expect(store.writes).toBe(1);
      expect(vault.revision()).toBe(4);
    });

    it('a save invoked before a lock never reaches the core or storage', async () => {
      await unlockedWith(3);
      const session = sessions[sessions.length - 1];
      const shown = vault.previewPassword(PASSWORD_PRESETS.default);
      const save = vault.savePreview('password', shown, 'gen');
      vault.lock();
      await expect(save).rejects.toBeInstanceOf(StaleWorkError);
      expect(session.savePreviewCalls).toBe(0);
      expect(store.writes).toBe(0);
      expect(() => vault.previewPassword(PASSWORD_PRESETS.default)).toThrow(LockedError);
    });

    it('lock during the write: success is never reported and the freed session is not committed', async () => {
      await unlockedWith(3);
      const session = sessions[sessions.length - 1];
      const shown = vault.previewPassword(PASSWORD_PRESETS.default);
      const hold = deferred();
      store.gate = hold.promise;
      const save = vault.savePreview('password', shown, 'gen');
      for (let i = 0; i < 50 && session.pending === null; i++) await new Promise((r) => setTimeout(r, 0));
      vault.lock();
      store.gate = null;
      hold.resolve();
      await expect(save).rejects.toBeInstanceOf(StaleWorkError);
      expect(session.revision()).toBe(3); // never committed
      expect(vault.status()).toBe('locked');
      expect(vault.items()).toEqual([]);
    });

    it('a stale tab cannot save a preview', async () => {
      await unlockedWith(3);
      const shown = vault.previewPassword(PASSWORD_PRESETS.default);
      vault.status.set('stale');
      await expect(vault.savePreview('password', shown, 'gen')).rejects.toBeInstanceOf(ConflictError);
      expect(store.writes).toBe(0);
    });
  });
});
