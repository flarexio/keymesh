/**
 * Vault session lifecycle for the browser demo.
 *
 * - The key provider is DEVELOPMENT ONLY and lives in WASM memory; its key is
 *   never visible to JavaScript, the URL, storage or logs.
 * - Every mutation runs inside the Rust core, is sealed there and persisted
 *   to IndexedDB with compare-and-swap; the session revision only advances
 *   after the write succeeded.
 * - `lock()` drops the decrypted vault in WASM and bumps an epoch: results of
 *   any asynchronous work started before the lock are discarded.
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
  | 'stale' // another writer changed storage; reload required
  | 'failed';

export type KeyMode = 'ephemeral' | 'synthetic-fixture';

export class LockedError extends Error {
  constructor() {
    super('The vault is locked.');
    this.name = 'LockedError';
  }
}

/** Thrown when async work finished after a lock/reload; result discarded. */
export class StaleWorkError extends Error {
  constructor() {
    super('The operation was cancelled because the vault was locked.');
    this.name = 'StaleWorkError';
  }
}

/** Encrypted-envelope storage; tests may provide another IDBFactory. */
export const VAULT_STORE = new InjectionToken<VaultStore>('keymesh.vault-store', {
  providedIn: 'root',
  factory: () => new VaultStore(indexedDB),
});

function message(e: unknown): string {
  return e instanceof Error ? e.message : 'unexpected error';
}

@Injectable({ providedIn: 'root' })
export class VaultService {
  private readonly clock = inject(CLOCK);
  private readonly store = inject(VAULT_STORE);
  private core: Core | null = null;
  private key: DemoKeyProvider | null = null;
  private session: VaultSession | null = null;
  private epoch = 0;
  private queue: Promise<unknown> = Promise.resolve();
  private channel: BroadcastChannel | null =
    typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('keymesh-vault');

  readonly status = signal<Status>('loading');
  readonly stored = signal<EnvelopeInfo | null>(null);
  readonly keyMode = signal<KeyMode | null>(null);
  readonly error = signal<string | null>(null);
  readonly notice = signal<string | null>(null);
  readonly query = signal('');
  readonly kindFilter = signal<ItemKind | ''>('');
  readonly items = signal<Summary[]>([]);
  readonly revision = signal(0);
  /** Incremented whenever item data changes, for views to refresh. */
  readonly version = signal(0);
  readonly unlocked = computed(() => this.status() === 'unlocked');
  readonly maxBytes = signal(64 * 1024 * 1024);

  constructor() {
    this.channel?.addEventListener('message', (ev: MessageEvent) => {
      const d = ev.data as { vaultId?: string; revision?: number } | null;
      if (!d) return;
      if (
        this.session &&
        this.status() === 'unlocked' &&
        d.vaultId === this.stored()?.vault_id &&
        typeof d.revision === 'number' &&
        d.revision !== this.revision()
      ) {
        this.status.set('stale');
      }
    });
  }

  async init(): Promise<void> {
    try {
      this.core = await loadCore();
      this.maxBytes.set(this.core.maxEnvelopeBytes());
      await this.refreshStored();
    } catch (e) {
      this.error.set(`Failed to start: ${message(e)}`);
      this.status.set('failed');
    }
  }

  private c(): Core {
    if (!this.core) throw new Error('core not loaded');
    return this.core;
  }

  private s(): VaultSession {
    if (!this.session || this.status() === 'locked') throw new LockedError();
    return this.session;
  }

  private async refreshStored(): Promise<void> {
    const rec = await this.store.read();
    if (!rec) {
      this.stored.set(null);
      this.status.set('empty');
      return;
    }
    this.stored.set(this.info(rec.bytes));
    this.status.set(this.key ? 'locked' : 'stored');
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

  private setSession(s: VaultSession, key: DemoKeyProvider): void {
    this.session?.free();
    this.session = s;
    this.key = key;
    this.keyMode.set(key.mode as KeyMode);
    this.revision.set(s.revision());
    this.status.set('unlocked');
    this.error.set(null);
    this.refreshList();
  }

  /** New empty vault, persisted immediately. Refuses if one is stored. */
  async startNew(mode: KeyMode): Promise<void> {
    return this.run(async () => {
      const key = this.provider(mode);
      const s = this.c().VaultSession.create(key);
      const sealed = s.seal(key);
      const bytes = sealed.bytes;
      const revision = sealed.revision;
      sealed.free();
      await this.store.create(this.record(bytes));
      s.commit(revision);
      this.stored.set(this.info(bytes));
      this.setSession(s, key);
      this.broadcast();
    });
  }

  /** Decrypt the stored envelope. Fixture key (after reload) or the key
   *  still held in memory (unlock after lock). */
  async openStored(): Promise<void> {
    return this.run(async () => {
      const rec = await this.store.read();
      if (!rec) throw new Error('No stored demo vault.');
      const key =
        this.key && this.key.keyId === rec.kekId
          ? this.key
          : rec.kekId === FIXTURE_KEY_ID
            ? this.provider('synthetic-fixture')
            : null;
      if (!key) {
        throw new Error(
          'This demo vault was encrypted with an ephemeral key that no longer exists. It cannot be opened.',
        );
      }
      const s = this.c().VaultSession.open(rec.bytes, key);
      this.stored.set(this.info(rec.bytes));
      this.setSession(s, key);
    });
  }

  /** Remove decrypted state. Pending async results are discarded. */
  lock(): void {
    this.epoch++;
    this.session?.lock();
    this.session?.free();
    this.session = null;
    this.items.set([]);
    this.query.set('');
    this.notice.set(null);
    this.version.update((v) => v + 1);
    this.status.set(this.stored() ? 'locked' : 'empty');
  }

  /** Discard the stored demo vault (and the in-memory key). */
  async discard(): Promise<void> {
    this.lock();
    this.key?.free();
    this.key = null;
    this.keyMode.set(null);
    await this.store.clear();
    this.stored.set(null);
    this.status.set('empty');
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
   * Apply `fn` in the core, seal, persist with compare-and-swap, then commit
   * the revision. Mutations are serialized. If persisting fails the in-memory
   * change is not trusted: the session is marked stale and must be reloaded.
   */
  private mutate<T>(fn: (s: VaultSession) => T): Promise<T> {
    return this.run(async () => {
      if (this.status() === 'stale') throw new ConflictError();
      const s = this.s();
      const key = this.key!;
      const epoch = this.epoch;
      const expected = s.revision();
      const result = fn(s);
      const sealed = s.seal(key);
      const revision = sealed.revision;
      const bytes = sealed.bytes;
      sealed.free();
      try {
        await this.store.compareAndPut(expected, this.record(bytes));
      } catch (e) {
        // The in-memory change was not persisted: never keep editing on top
        // of it. Reload from storage is required.
        if (epoch === this.epoch) this.status.set('stale');
        throw e;
      }
      if (epoch !== this.epoch) throw new StaleWorkError();
      s.commit(revision);
      this.revision.set(revision);
      this.stored.set(this.info(bytes));
      this.version.update((v) => v + 1);
      this.refreshList();
      this.broadcast();
      return result;
    });
  }

  private broadcast(): void {
    const info = this.stored();
    this.channel?.postMessage({ vaultId: info?.vault_id, revision: info?.revision });
  }

  /** Serialize async work; report errors without leaking values. */
  private run<T>(fn: () => Promise<T>): Promise<T> {
    const p = this.queue.then(fn, fn);
    this.queue = p.catch(() => undefined);
    return p;
  }

  // --- backup / restore ------------------------------------------------------

  /** The stored encrypted envelope, exactly as persisted. */
  async backupBytes(): Promise<Uint8Array> {
    if (this.status() !== 'unlocked') throw new LockedError();
    const rec = await this.store.read();
    if (!rec) throw new Error('Nothing stored to back up.');
    if (rec.revision !== this.revision()) throw new ConflictError();
    return rec.bytes;
  }

  /**
   * Restore an encrypted backup. It must decrypt with the current demo key
   * (or the synthetic fixture key when no session exists) BEFORE anything is
   * written; on any failure the stored vault is untouched.
   */
  async restore(file: File): Promise<void> {
    return this.run(async () => {
      if (file.size > this.maxBytes()) throw new Error('Backup file is too large.');
      const bytes = new Uint8Array(await file.arrayBuffer());
      const key = this.key ?? this.provider('synthetic-fixture');
      let s: VaultSession;
      try {
        s = this.c().VaultSession.open(bytes, key);
      } catch (e) {
        throw new Error(`Backup rejected, nothing was changed: ${message(e)}`);
      }
      this.epoch++;
      await this.store.replace(this.record(bytes));
      this.stored.set(this.info(bytes));
      this.setSession(s, key);
      this.broadcast();
    });
  }

  /** Re-read storage after a conflict; unsaved in-memory changes are dropped. */
  async reload(): Promise<void> {
    this.lock();
    await this.openStored();
  }
}
