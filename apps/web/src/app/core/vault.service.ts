/**
 * Vault session lifecycle for the browser demo.
 *
 * - The key provider is DEVELOPMENT ONLY and lives in WASM memory; its key is
 *   never visible to JavaScript, the URL, storage or logs.
 * - Every mutation runs inside the Rust core, is sealed there and persisted
 *   to IndexedDB with an exact-snapshot compare-and-swap; the session revision
 *   only advances after the write succeeded.
 * - Lock wins: every asynchronous operation captures the lock generation
 *   (`epoch`) when it is *invoked* and re-checks it before it starts and after
 *   every `await`. Work invoked before a lock never installs state or reveals
 *   data afterwards, and is not persisted where cancellation is still possible.
 */
import { Injectable, InjectionToken, computed, inject, signal } from '@angular/core';
import { CLOCK } from './clock';
import { ConflictError, StoredVault, VaultStore } from './vault-store';
import { Core, loadCore } from './wasm';
import type { DemoKeyProvider, VaultSession } from './wasm-pkg/keymesh_wasm';
import {
  EPHEMERAL_KEY_ID,
  EnvelopeInfo,
  FIXTURE_KEY_ID,
  ItemInput,
  ItemKind,
  ItemView,
  Summary,
} from './types';

export type Status =
  | 'loading'
  | 'empty' // nothing stored
  | 'stored' // envelope stored, no session
  | 'locked' // session locked, provider still in memory
  | 'unlocked'
  | 'stale' // storage changed elsewhere; reload required
  | 'failed';

export type KeyMode = 'ephemeral' | 'synthetic-fixture';

export class LockedError extends Error {
  constructor() {
    super('The vault is locked.');
    this.name = 'LockedError';
  }
}

/** Known, secret-free failure with a stable code for localized messages. */
export type VaultErrorCode =
  | 'noStoredVault'
  | 'ephemeralKeyLost'
  | 'restoreNotAllowed'
  | 'backupTooLarge'
  | 'backupRejected';

export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

/** Work invoked before a lock (or reload/restore/discard); never applied. */
export class StaleWorkError extends Error {
  constructor() {
    super('The operation was cancelled because the vault was locked or replaced.');
    this.name = 'StaleWorkError';
  }
}

/** Encrypted-envelope storage; tests may provide another IDBFactory. */
export const VAULT_STORE = new InjectionToken<VaultStore>('keymesh.vault-store', {
  providedIn: 'root',
  factory: () => new VaultStore(indexedDB),
});

/** Loads the compiled core; tests may substitute a controllable fake. */
export const CORE_LOADER = new InjectionToken<() => Promise<Core>>('keymesh.core-loader', {
  providedIn: 'root',
  factory: () => loadCore,
});

function message(e: unknown): string {
  return e instanceof Error ? e.message : 'unexpected error';
}

function sameBytes(a: Uint8Array | null, b: Uint8Array | null): boolean {
  if (!a || !b || a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

type Guard = () => void;

@Injectable({ providedIn: 'root' })
export class VaultService {
  private readonly clock = inject(CLOCK);
  private readonly store = inject(VAULT_STORE);
  private readonly loadCore = inject(CORE_LOADER);
  private core: Core | null = null;
  private key: DemoKeyProvider | null = null;
  private session: VaultSession | null = null;
  /** Exact stored envelope this tab last read or wrote (CAS snapshot). */
  private snapshot: Uint8Array | null = null;
  private epoch = 0;
  private queue: Promise<unknown> = Promise.resolve();
  private channel: BroadcastChannel | null =
    typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('keymesh-vault');

  readonly status = signal<Status>('loading');
  readonly stored = signal<EnvelopeInfo | null>(null);
  readonly keyMode = signal<KeyMode | null>(null);
  readonly error = signal<string | null>(null);
  readonly query = signal('');
  readonly kindFilter = signal<ItemKind | ''>('');
  readonly items = signal<Summary[]>([]);
  readonly revision = signal(0);
  /** Incremented whenever item data changes, for views to refresh. */
  readonly version = signal(0);
  readonly unlocked = computed(() => this.status() === 'unlocked');
  readonly maxBytes = signal(64 * 1024 * 1024);

  constructor() {
    // Any write elsewhere: compare exact bytes (revisions can repeat after a
    // restore), and stop editing if storage no longer matches our snapshot.
    this.channel?.addEventListener('message', () => void this.checkExternalChange());
  }

  async init(): Promise<void> {
    try {
      this.core = await this.loadCore();
      this.maxBytes.set(this.core.maxEnvelopeBytes());
      await this.run(async (guard) => {
        const rec = await this.store.read();
        guard();
        this.showStored(rec);
      });
    } catch (e) {
      this.error.set(`Failed to start: ${message(e)}`);
      this.status.set('failed');
    }
  }

  private async checkExternalChange(): Promise<void> {
    if (!this.session || this.status() !== 'unlocked') return;
    const epoch = this.epoch;
    const rec = await this.store.read();
    if (epoch !== this.epoch || this.status() !== 'unlocked') return;
    if (!rec || !sameBytes(rec.bytes, this.snapshot)) this.status.set('stale');
  }

  private c(): Core {
    if (!this.core) throw new Error('core not loaded');
    return this.core;
  }

  private s(): VaultSession {
    if (!this.session || this.status() === 'locked') throw new LockedError();
    return this.session;
  }

  private showStored(rec: StoredVault | null): void {
    this.snapshot = rec?.bytes ?? null;
    this.stored.set(rec ? this.info(rec.bytes) : null);
    this.status.set(rec ? (this.key ? 'locked' : 'stored') : 'empty');
  }

  private info(bytes: Uint8Array): EnvelopeInfo {
    return JSON.parse(this.c().inspectEnvelope(bytes)) as EnvelopeInfo;
  }

  private provider(mode: KeyMode): DemoKeyProvider {
    return mode === 'ephemeral'
      ? this.c().DemoKeyProvider.ephemeral()
      : this.c().DemoKeyProvider.syntheticFixture();
  }

  /** Whether the stored envelope can be opened with a key we can provide. */
  canOpenStored(): boolean {
    const info = this.stored();
    if (!info) return false;
    if (info.kek_id === FIXTURE_KEY_ID) return true;
    return !!this.key && this.key.keyId === info.kek_id;
  }

  storedNeedsLostKey(): boolean {
    const info = this.stored();
    return !!info && info.kek_id === EPHEMERAL_KEY_ID && !this.key;
  }

  private record(bytes: Uint8Array): StoredVault {
    const info = this.info(bytes);
    return { bytes, vaultId: info.vault_id, kekId: info.kek_id, revision: info.revision };
  }

  /** Install a decrypted session. Invalidates work invoked before it. */
  private install(s: VaultSession, key: DemoKeyProvider, bytes: Uint8Array): void {
    this.epoch++;
    this.session?.free();
    this.session = s;
    if (this.key && this.key !== key) this.key.free();
    this.key = key;
    this.snapshot = bytes;
    this.stored.set(this.info(bytes));
    this.keyMode.set(key.mode as KeyMode);
    this.revision.set(s.revision());
    this.status.set('unlocked');
    this.error.set(null);
    this.version.update((v) => v + 1);
    this.refreshList();
  }

  /**
   * Serialize async work. The lock generation is captured at invocation; the
   * returned guard throws StaleWorkError once a lock/reload/restore happened.
   */
  private run<T>(fn: (guard: Guard) => Promise<T>): Promise<T> {
    const epoch = this.epoch;
    const guard: Guard = () => {
      if (epoch !== this.epoch) throw new StaleWorkError();
    };
    const p = this.queue.then(() => {
      guard();
      return fn(guard);
    });
    this.queue = p.catch(() => undefined);
    return p;
  }

  /** New empty vault, persisted immediately. Refuses if one is stored. */
  startNew(mode: KeyMode): Promise<void> {
    return this.run(async (guard) => {
      const key = this.provider(mode);
      const s = this.c().VaultSession.create(key);
      const sealed = s.seal(key);
      const bytes = sealed.bytes;
      const revision = sealed.revision;
      sealed.free();
      try {
        guard();
        await this.store.create(this.record(bytes));
      } catch (e) {
        s.free();
        key.free();
        throw e;
      }
      if (this.isStale(guard)) {
        // Persisted, but a lock won: keep the key so it can be unlocked.
        s.free();
        this.key = key;
        this.keyMode.set(key.mode as KeyMode);
        throw new StaleWorkError();
      }
      s.commit(revision);
      this.install(s, key, bytes);
      this.broadcast();
    });
  }

  private isStale(guard: Guard): boolean {
    try {
      guard();
      return false;
    } catch {
      return true;
    }
  }

  /** Decrypt the stored envelope: the synthetic fixture key (after reload)
   *  or the key still held in memory (unlock after lock). */
  openStored(): Promise<void> {
    return this.run(async (guard) => {
      const rec = await this.store.read();
      guard();
      if (!rec) throw new VaultError('noStoredVault', 'No stored demo vault.');
      const key =
        this.key && this.key.keyId === rec.kekId
          ? this.key
          : rec.kekId === FIXTURE_KEY_ID
            ? this.provider('synthetic-fixture')
            : null;
      if (!key) {
        throw new VaultError(
          'ephemeralKeyLost',
          'This demo vault was encrypted with an ephemeral key that no longer exists. It cannot be opened.',
        );
      }
      this.install(this.c().VaultSession.open(rec.bytes, key), key, rec.bytes);
    });
  }

  /** Remove decrypted state. Every pending or queued operation is cancelled. */
  lock(): void {
    this.epoch++;
    this.session?.lock();
    this.session?.free();
    this.session = null;
    this.items.set([]);
    this.query.set('');
    this.version.update((v) => v + 1);
    this.status.set(this.stored() ? 'locked' : 'empty');
  }

  /** Discard the stored demo vault, but only the one this tab last saw. */
  discard(): Promise<void> {
    const expected = this.snapshot;
    this.lock();
    return this.run(async (guard) => {
      await this.store.compareAndClear(expected);
      guard();
      this.key?.free();
      this.key = null;
      this.keyMode.set(null);
      this.showStored(null);
    });
  }

  // --- reads ---------------------------------------------------------------

  refreshList(): void {
    if (!this.session || this.status() !== 'unlocked') return;
    this.items.set(JSON.parse(this.s().list(this.query(), this.kindFilter())) as Summary[]);
  }

  /** Summaries of one kind, independent of the current search. */
  summaries(kind: ItemKind): Summary[] {
    return JSON.parse(this.s().list('', kind)) as Summary[];
  }

  get(id: string): ItemView {
    return JSON.parse(this.s().get(id)) as ItemView;
  }

  reveal(id: string, slot: string): string {
    return this.s().reveal(id, slot);
  }

  totp(id: string): { code: string; remaining: number } {
    const t = this.s().totpCode(id, this.clock.nowSeconds());
    const r = { code: t.code, remaining: t.remaining };
    t.free();
    return r;
  }

  generatePassword(profile: 'default' | 'strong'): string {
    if (this.status() !== 'unlocked') throw new LockedError();
    return this.c().generatePassword(profile, 0, '');
  }

  generateRandomSecret(bytes: number, encoding: string): string {
    if (this.status() !== 'unlocked') throw new LockedError();
    return this.c().generateRandomSecret(bytes, encoding);
  }

  // --- mutations -------------------------------------------------------------

  createItem(input: ItemInput): Promise<string> {
    return this.mutate((s) => s.createItem(JSON.stringify(input)));
  }

  updateItem(id: string, input: ItemInput): Promise<void> {
    return this.mutate((s) => s.updateItem(id, JSON.stringify(input)));
  }

  deleteItem(id: string): Promise<void> {
    return this.mutate((s) => s.deleteItem(id));
  }

  createTotp(title: string, input: string, issuer: string, account: string): Promise<string> {
    return this.mutate((s) => s.createTotp(title, input, issuer, account));
  }

  generateEd25519(title: string, comment: string): Promise<string> {
    return this.mutate((s) => s.generateEd25519(title, comment));
  }

  generateSecretItem(title: string, bytes: number, encoding: string, service: string) {
    return this.mutate((s) => s.generateSecretItem(title, bytes, encoding, service));
  }

  generatePasswordItem(title: string, profile: string, service: string) {
    return this.mutate((s) => s.generatePasswordItem(title, profile, service));
  }

  /**
   * Apply `fn` in the core, seal, persist with compare-and-swap against the
   * exact snapshot, then commit. If sealing fails (e.g. size limit) the core
   * has already rolled the change back. If persisting fails the in-memory
   * change is not trusted: the session is marked stale and must be reloaded.
   */
  private mutate<T>(fn: (s: VaultSession) => T): Promise<T> {
    return this.run(async (guard) => {
      if (this.status() === 'stale') throw new ConflictError();
      const s = this.s();
      const key = this.key!;
      const expected = this.snapshot;
      const result = fn(s);
      let bytes: Uint8Array;
      let revision: number;
      try {
        const sealed = s.seal(key);
        bytes = sealed.bytes;
        revision = sealed.revision;
        sealed.free();
      } catch (e) {
        this.version.update((v) => v + 1);
        this.refreshList();
        throw e;
      }
      try {
        await this.store.compareAndSwap(expected, this.record(bytes));
      } catch (e) {
        if (!this.isStale(guard)) this.status.set('stale');
        throw e;
      }
      // Locked while writing: the ciphertext is stored (unlock re-reads it),
      // but the freed session is never touched again.
      guard();
      s.commit(revision);
      this.snapshot = bytes;
      this.revision.set(revision);
      this.stored.set(this.info(bytes));
      this.version.update((v) => v + 1);
      this.refreshList();
      this.broadcast();
      return result;
    });
  }

  private broadcast(): void {
    this.channel?.postMessage({ changed: true });
  }

  // --- backup / restore ------------------------------------------------------

  /** The stored encrypted envelope, exactly as persisted by this session. */
  backupBytes(): Promise<Uint8Array> {
    return this.run(async (guard) => {
      if (this.status() !== 'unlocked') throw new LockedError();
      const rec = await this.store.read();
      guard();
      if (!rec || !sameBytes(rec.bytes, this.snapshot)) {
        this.status.set('stale');
        throw new ConflictError();
      }
      return rec.bytes;
    });
  }

  /**
   * Restore an encrypted backup. Allowed from an unlocked, non-stale session
   * (replacing exactly the envelope this tab last saw) or into empty storage
   * (synthetic fixture key). The file must decrypt BEFORE anything is written;
   * the write is a compare-and-swap; a lock at any point wins.
   */
  restore(file: File): Promise<void> {
    return this.run(async (guard) => {
      const status = this.status();
      if (status === 'stale') {
        throw new ConflictError('This tab is out of date. Reload from storage before restoring.', 'staleTab');
      }
      if (status !== 'unlocked' && status !== 'empty') {
        throw new VaultError('restoreNotAllowed', 'Restore needs an unlocked vault or empty storage.');
      }
      if (file.size > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
      const expected = status === 'unlocked' ? this.snapshot : null;
      const bytes = new Uint8Array(await file.arrayBuffer());
      guard();
      if (bytes.length > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
      const key = this.key ?? this.provider('synthetic-fixture');
      let candidate: VaultSession;
      try {
        candidate = this.c().VaultSession.open(bytes, key);
      } catch (e) {
        if (key !== this.key) key.free();
        throw new VaultError('backupRejected', `Backup rejected, nothing was changed: ${message(e)}`);
      }
      const drop = () => {
        candidate.free();
        if (key !== this.key) key.free();
      };
      try {
        guard();
        await this.store.compareAndSwap(expected, this.record(bytes));
      } catch (e) {
        drop();
        if (e instanceof ConflictError && !this.isStale(guard) && status === 'unlocked') {
          this.status.set('stale');
        }
        throw e;
      }
      if (this.isStale(guard)) {
        // Lock won while the (already verified) backup was being written:
        // nothing is installed; unlocking later reads the stored envelope.
        drop();
        throw new StaleWorkError();
      }
      this.install(candidate, key, bytes);
      this.broadcast();
    });
  }

  /** Re-read storage after a conflict; unsaved in-memory changes are dropped. */
  async reload(): Promise<void> {
    this.lock();
    await this.openStored();
  }
}
