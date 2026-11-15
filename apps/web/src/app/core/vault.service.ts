/**
 * Vault session lifecycle in the browser.
 *
 * Two separate vaults, each in its own IndexedDB database:
 * - **Demo vault** (envelope v1): a DEVELOPMENT ONLY key provider (public
 *   fixture key or a memory-only ephemeral key) that lives in WASM memory;
 *   its key is never visible to JavaScript, the URL, storage or logs.
 * - **Password vault** (envelope v2; experimental until independently
 *   reviewed): a master password and a recovery code, each wrapping the
 *   vault's random data key. Only available in a secure context (HTTPS or
 *   this device); on a plain-HTTP address every password-vault operation is
 *   refused and the demo stays usable. Argon2id runs in a worker
 *   (`KDF_RUNNER`); one credential operation runs at a time, and a lock
 *   terminates it. A demo vault is never converted into a password vault.
 *
 * - Every mutation runs inside the Rust core, is sealed there and persisted
 *   to IndexedDB with an exact-snapshot compare-and-swap; the session revision
 *   only advances after the write succeeded.
 * - Lock wins: every asynchronous operation captures the lock generation
 *   (`epoch`) when it is *invoked* and re-checks it before it starts and after
 *   every `await`. Work invoked before a lock never installs state or reveals
 *   data afterwards. The guard also reaches the storage write, which re-checks
 *   it right before `put`: a write still waiting is cancelled and storage stays
 *   unchanged. Only a write that already committed lands; it is reported as
 *   `StaleWorkError(committed = true)`, never as success.
 */
import { Injectable, InjectionToken, computed, inject, signal } from '@angular/core';
import { CLOCK } from './clock';
import { KDF_RUNNER, KdfBusyError, KdfCancelledError } from './kdf';
import { ConflictError, StoredVault, VaultStore } from './vault-store';
import type { PasswordOptions } from './password-options';
import { Core, loadCore } from './wasm';
import type { DemoKeyProvider, VaultSession } from './wasm-pkg/keymesh_wasm';
import { FLAG_BE, FLAG_UV, PrfSlotInfo, WEBAUTHN, b64u, flagsOf, prfEnabled, prfFirst, randomBytes } from './quick-unlock';
import type { MessageEncoding, MessagePreview, PassphraseOptions, PassphraseSummary, SignatureOut, Verdict } from './types';
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

export type KeyMode = 'ephemeral' | 'synthetic-fixture' | 'protected';
export type DemoKeyMode = Exclude<KeyMode, 'protected'>;

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
  | 'backupRejected'
  | 'insecureContext'
  | 'protectedExists'
  | 'noPendingVault'
  | 'wrongPassword'
  | 'wrongRecovery'
  | 'demoBackup'
  | 'protectedBackup'
  | 'samePassword'
  | 'rotatedWhileLocked'
  | 'rotationUncertain'
  | 'quickUnlockUnsupported'
  | 'quickUnlockNone'
  | 'quickUnlockFailed'
  | 'quickUnlockOrphan'
  | 'quickUnlockUncertain'
  | 'quickUnlockRevokeRequired'
  | 'busy';

export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'VaultError';
  }
}

/**
 * Work invoked before a lock (or reload/restore/discard); never applied to
 * the session. `committed`: its encrypted write had already been stored
 * before the lock (unlocking shows it); otherwise nothing was written.
 */
export class StaleWorkError extends Error {
  constructor(readonly committed = false) {
    super(
      committed
        ? 'The vault was locked after the change was stored.'
        : 'The operation was cancelled because the vault was locked or replaced.',
    );
    this.name = 'StaleWorkError';
  }
}

/** Encrypted-envelope storage; tests may provide another IDBFactory. */
export const VAULT_STORE = new InjectionToken<VaultStore>('keymesh.vault-store', {
  providedIn: 'root',
  factory: () => new VaultStore(indexedDB),
});

/** Password-vault (v2) envelopes; never shared with the demo database. */
export const PROTECTED_VAULT_STORE = new InjectionToken<VaultStore>('keymesh.protected-vault-store', {
  providedIn: 'root',
  factory: () => new VaultStore(indexedDB, 'keymesh-vault'),
});

/**
 * Whether the page is a secure context (W3C Secure Contexts: HTTPS, or
 * loopback). Plain HTTP on a LAN/VPN address is not.
 */
export const SECURE_CONTEXT = new InjectionToken<boolean>('keymesh.secure-context', {
  providedIn: 'root',
  factory: () => globalThis.isSecureContext === true,
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

export type CredentialNoticeCode =
  | 'rotatedWhileLocked'
  | 'rotationUncertain'
  | 'quickUnlockSavedWhileLocked'
  | 'quickUnlockOrphan'
  | 'quickUnlockUncertain';
export interface CredentialNotice {
  code: CredentialNoticeCode;
  /** Sequence number of the operation that produced it. */
  seq: number;
  /** Non-secret passkey metadata for the instructions (label, creation time). */
  passkey?: { label: string; at: number };
  /** Public credential id (base64url) still to reconcile at the next unlock. */
  credentialId?: string;
}

@Injectable({ providedIn: 'root' })
export class VaultService {
  private readonly clock = inject(CLOCK);
  private readonly demoStore = inject(VAULT_STORE);
  private readonly protStore = inject(PROTECTED_VAULT_STORE);
  private readonly kdf = inject(KDF_RUNNER);
  private readonly webauthn = inject(WEBAUTHN);
  /** Secure context: password vaults are allowed. */
  readonly secure = inject(SECURE_CONTEXT);
  private readonly loadCore = inject(CORE_LOADER);
  private core: Core | null = null;
  private key: DemoKeyProvider | null = null;
  private session: VaultSession | null = null;
  /** Which vault the open session (or the next operation) belongs to. */
  private active: 'demo' | 'protected' = 'demo';
  /** Exact stored envelopes this tab last read or wrote (CAS snapshots). */
  private demoSnap: Uint8Array | null = null;
  private protSnap: Uint8Array | null = null;
  /** A new password vault waiting for its recovery code to be confirmed. */
  private creating: VaultSession | null = null;
  private credentialOp = false;

  private get store(): VaultStore {
    return this.active === 'protected' ? this.protStore : this.demoStore;
  }
  private get snapshot(): Uint8Array | null {
    return this.active === 'protected' ? this.protSnap : this.demoSnap;
  }
  private set snapshot(v: Uint8Array | null) {
    if (this.active === 'protected') this.protSnap = v;
    else this.demoSnap = v;
  }
  private epoch = 0;
  private queue: Promise<unknown> = Promise.resolve();
  private channel: BroadcastChannel | null =
    typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('keymesh-vault');

  readonly status = signal<Status>('loading');
  /** Demo vault stored in this browser. */
  readonly stored = signal<EnvelopeInfo | null>(null);
  /** Password vault stored in this browser (only read in a secure context). */
  readonly protectedStored = signal<EnvelopeInfo | null>(null);
  /** A new password vault is waiting for recovery-code confirmation. */
  readonly confirmingNewVault = signal(false);
  /** A password/recovery operation (KDF) is running. */
  readonly credentialBusy = signal(false);
  /** A password vault was locked by "Load latest version"; unlock to continue. */
  readonly protectedReloaded = signal(false);
  /** The open session is a password vault. */
  readonly isProtected = computed(() => this.keyMode() === 'protected');
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
  /** The compiled core is loaded (policy checks and generators available). */
  readonly coreReady = signal(false);
  /**
   * Non-secret outcome of a credential operation whose result is only known
   * after the vault locked (a rotation that landed during a lock, or one whose
   * outcome could not be read back). Kept here, not in the view that started
   * it (that view is destroyed by the lock), so the locked screen can tell
   * the user which credentials to try. Holds a code only, never a secret.
   * Cleared when acknowledged or by a successful password-vault unlock.
   */
  readonly credentialNotice = signal<CredentialNotice | null>(null);
  /** Order of credential operations, so an older one never replaces a newer notice. */
  private opSeq = 0;

  credentialOpSeq(): number {
    return this.opSeq;
  }

  /** Record `code` for the operation numbered `seq`, unless a newer one already left a notice. */
  recordNotice(code: CredentialNoticeCode, seq: number, extra: Partial<CredentialNotice> = {}): void {
    const cur = this.credentialNotice();
    if (cur && cur.seq > seq) return;
    this.credentialNotice.set({ ...extra, code, seq });
  }

  acknowledgeNotice(): void {
    this.credentialNotice.set(null);
  }

  /**
   * A password vault opened (with whichever credential worked). Rotation
   * notices are answered by that. A pending passkey enrolment is reconciled
   * against the STORED slots: present → it took effect (no orphan, nothing
   * to delete); absent → only now is it reported as an orphan to delete in
   * the device/provider settings. An orphan notice stays until acknowledged.
   */
  private reconcileNotice(bytes: Uint8Array): void {
    const n = this.credentialNotice();
    if (!n) return;
    if (n.code === 'quickUnlockOrphan') return;
    if (n.code === 'quickUnlockUncertain' && n.credentialId) {
      let present = false;
      try {
        present = (JSON.parse(this.c().prfRequest(bytes)) as PrfSlotInfo[]).some((x) => x.credential_id === n.credentialId);
      } catch {
        return; // can't tell yet: keep the pending notice
      }
      this.credentialNotice.set(present ? null : { code: 'quickUnlockOrphan', seq: n.seq, passkey: n.passkey });
      return;
    }
    this.credentialNotice.set(null);
  }

  constructor() {
    // Any write elsewhere: compare exact bytes (revisions can repeat after a
    // restore), and stop editing if storage no longer matches our snapshot.
    this.channel?.addEventListener('message', () => void this.checkExternalChange());
  }

  async init(): Promise<void> {
    try {
      this.core = await this.loadCore();
      this.maxBytes.set(this.core.maxEnvelopeBytes());
      this.coreReady.set(true);
      await this.run(async (guard) => {
        if (this.secure) {
          const prot = await this.protStore.read();
          guard();
          this.protSnap = prot?.bytes ?? null;
          this.protectedStored.set(prot ? this.info(prot.bytes) : null);
          this.refreshStoredQuickUnlock(prot?.bytes ?? null);
        }
        const rec = await this.demoStore.read();
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
    // Auto-lock: a passed deadline locks BEFORE any secret is used.
    if (!this.freshCheck()) throw new LockedError();
    return this.session;
  }

  /** Auto-lock hooks (core/auto-lock.ts): checked before every session use. */
  private freshCheck: () => boolean = () => true;
  private sessionStarted: () => void = () => undefined;
  setFreshnessCheck(fresh: () => boolean, started: () => void = () => undefined): void {
    this.freshCheck = fresh;
    this.sessionStarted = started;
  }

  /** Demo vault state after a read (start screen). */
  private showStored(rec: StoredVault | null): void {
    this.demoSnap = rec?.bytes ?? null;
    this.stored.set(rec ? this.info(rec.bytes) : null);
    this.status.set(rec ? (this.key ? 'locked' : 'stored') : 'empty');
  }

  private info(bytes: Uint8Array): EnvelopeInfo {
    return JSON.parse(this.c().inspectEnvelope(bytes)) as EnvelopeInfo;
  }

  private provider(mode: DemoKeyMode): DemoKeyProvider {
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
    return { bytes, vaultId: info.vault_id, kekId: info.kek_id ?? 'v2-key-slots', revision: info.revision };
  }

  private setStoredInfo(bytes: Uint8Array): void {
    (this.active === 'protected' ? this.protectedStored : this.stored).set(this.info(bytes));
    if (this.active === 'protected') this.refreshStoredQuickUnlock(bytes);
  }

  /**
   * Install a decrypted session (`key` null: password vault). Invalidates
   * work invoked before it.
   */
  private install(s: VaultSession, key: DemoKeyProvider | null, bytes: Uint8Array): void {
    this.epoch++;
    this.sessionStarted(); // fresh deadlines BEFORE the session becomes usable
    this.session?.free();
    this.session = s;
    // A password session leaves the demo key alone (an ephemeral demo vault
    // stays openable after the password vault is locked).
    if (key) {
      if (this.key && this.key !== key) this.key.free();
      this.key = key;
    }
    this.active = key ? 'demo' : 'protected';
    if (!key) this.reconcileNotice(bytes);
    this.protectedReloaded.set(false);
    this.snapshot = bytes;
    this.setStoredInfo(bytes);
    this.keyMode.set(key ? (key.mode as KeyMode) : 'protected');
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

  /** New empty demo vault, persisted immediately. Refuses if one is stored. */
  startNew(mode: DemoKeyMode): Promise<void> {
    return this.run(async (guard) => {
      this.active = 'demo';
      const key = this.provider(mode);
      const s = this.c().VaultSession.create(key);
      const sealed = s.seal(key);
      const bytes = sealed.bytes;
      const revision = sealed.revision;
      sealed.free();
      try {
        await this.store.create(this.record(bytes), guard);
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
        throw new StaleWorkError(true);
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
      this.active = 'demo';
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

  /**
   * Remove decrypted state. Every pending or queued operation is cancelled,
   * including a running key derivation and an unconfirmed new vault.
   */
  lock(): void {
    this.epoch++;
    this.kdf.cancel();
    this.webauthnAbort?.abort();
    this.webauthnAbort = null;
    this.session?.lock();
    this.session?.free();
    this.session = null;
    this.creating?.lock();
    this.creating?.free();
    this.creating = null;
    this.confirmingNewVault.set(false);
    if (this.active === 'protected') {
      this.active = 'demo';
      this.keyMode.set(this.key ? (this.key.mode as KeyMode) : null);
    }
    this.items.set([]);
    this.query.set('');
    this.version.update((v) => v + 1);
    this.status.set(this.stored() ? (this.key ? 'locked' : 'stored') : 'empty');
  }

  /** Discard the stored demo vault, but only the one this tab last saw. */
  discard(): Promise<void> {
    this.lock();
    const expected = this.demoSnap;
    return this.run(async (guard) => {
      await this.store.compareAndClear(expected, guard);
      guard();
      this.key?.free();
      this.key = null;
      this.keyMode.set(null);
      this.showStored(null);
    });
  }

  // --- password vault (envelope v2) -------------------------------------------

  /** 1 (demo), 2 (password vault) or null if the bytes are not an envelope. */
  envelopeVersion(bytes: Uint8Array): number | null {
    try {
      return this.info(bytes).version ?? 1;
    } catch {
      return null;
    }
  }

  /** Version of a backup file the user picked (bounded read), or null. */
  async fileVersion(file: File): Promise<number | null> {
    if (file.size > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
    return this.envelopeVersion(new Uint8Array(await file.arrayBuffer()));
  }

  /** Throws a localized-code error when `password` can't be a new master password. */
  checkNewPassword(password: string): void {
    this.c().checkNewPassword(password);
  }

  private requireSecure(): void {
    if (!this.secure) {
      throw new VaultError('insecureContext', 'Password vaults need a secure (HTTPS) connection.');
    }
  }

  /**
   * One credential operation at a time, refused (not queued) while another
   * runs, so a double click can never start a second key derivation.
   */
  private credential<T>(fn: (guard: Guard) => Promise<T>): Promise<T> {
    try {
      this.requireSecure();
    } catch (e) {
      return Promise.reject(e);
    }
    if (this.credentialOp) return Promise.reject(new VaultError('busy', 'Another unlock is in progress.'));
    this.credentialOp = true;
    this.credentialBusy.set(true);
    return this.run(fn)
      .catch((e: unknown) => {
        if (e instanceof KdfCancelledError) throw new StaleWorkError();
        if (e instanceof KdfBusyError) throw new VaultError('busy', 'Another unlock is in progress.');
        throw e;
      })
      .finally(() => {
        this.credentialOp = false;
        this.credentialBusy.set(false);
      });
  }

  /**
   * Argon2id in the worker for a core-issued request. The lock generation is
   * re-checked when it returns; a stale result is zeroed and dropped.
   */
  private async derive(password: string, request: string, guard: Guard): Promise<Uint8Array> {
    const key = await this.kdf.derive(password, request);
    if (this.isStale(guard)) {
      key.fill(0);
      throw new StaleWorkError();
    }
    return key;
  }

  /**
   * Step 1 of creating a password vault: derive the password key and build
   * the vault in memory with a fresh recovery code. Nothing is stored until
   * `confirmNewVault` gets the recovery code back.
   */
  createProtected(password: string): Promise<void> {
    return this.credential(async (guard) => {
      this.checkNewPassword(password);
      const existing = await this.protStore.read();
      guard();
      if (existing) throw new VaultError('protectedExists', 'A password vault already exists in this browser.');
      const creation = new (this.c().ProtectedCreation)();
      try {
        const key = await this.derive(password, creation.request(), guard);
        try {
          const s = this.c().VaultSession.createProtected(creation, key);
          this.creating?.free();
          this.creating = s;
        } finally {
          key.fill(0);
        }
      } finally {
        creation.free();
      }
      this.confirmingNewVault.set(true);
    });
  }

  /** The new vault's id (for the emergency kit), or null. */
  newVaultId(): string | null {
    try {
      return this.creating?.vaultId() ?? null;
    } catch {
      return null;
    }
  }

  /** The new vault's recovery code, for display until it is confirmed. */
  newVaultRecoveryCode(): string {
    if (!this.creating) throw new VaultError('noPendingVault', 'No new vault is waiting.');
    return this.creating.shownRecoveryCode();
  }

  /**
   * Step 2: the core checks the typed code (by unwrapping the recovery slot),
   * then the empty vault is stored (only if no password vault exists) and
   * opened. A wrong code keeps the pending vault so it can be retried.
   */
  confirmNewVault(code: string): Promise<void> {
    return this.run(async (guard) => {
      this.requireSecure();
      const s = this.creating;
      if (!s) throw new VaultError('noPendingVault', 'No new vault is waiting.');
      s.confirmRecovery(code);
      const sealed = s.sealProtected();
      const bytes = sealed.bytes;
      const revision = sealed.revision;
      sealed.free();
      this.active = 'protected';
      await this.protStore.create(this.record(bytes), guard);
      if (this.isStale(guard)) throw new StaleWorkError(true);
      this.creating = null;
      this.confirmingNewVault.set(false);
      s.commit(revision);
      this.install(s, null, bytes);
      this.broadcast();
    });
  }

  /** Abandon a new vault before it was stored. */
  cancelNewVault(): void {
    this.creating?.lock();
    this.creating?.free();
    this.creating = null;
    this.confirmingNewVault.set(false);
  }

  /** Open the stored password vault after a reload or lock. */
  unlockWithPassword(password: string): Promise<void> {
    return this.credential(async (guard) => {
      const rec = await this.protStore.read();
      guard();
      if (!rec) throw new VaultError('noStoredVault', 'No stored vault.');
      const key = await this.derive(password, this.c().passwordRequest(rec.bytes), guard);
      let s: VaultSession;
      try {
        s = this.c().VaultSession.openWithPasswordKey(rec.bytes, key);
      } catch (e) {
        throw this.unlockError(e, 'wrongPassword');
      } finally {
        key.fill(0);
      }
      this.active = 'protected';
      this.protSnap = rec.bytes;
      this.install(s, null, rec.bytes);
    });
  }

  private unlockError(e: unknown, code: 'wrongPassword' | 'wrongRecovery'): unknown {
    return e instanceof Error && /^decryption failed/.test(e.message)
      ? new VaultError(code, 'The vault could not be opened with this credential.')
      : e;
  }

  /**
   * Forgot the password: open `bytes` with the recovery code, wrap the same
   * data key under a new password and store the result with a CAS against
   * `expected`. Shared by "reset password" and "restore with recovery code".
   */
  private async recoverInto(
    bytes: Uint8Array,
    expected: Uint8Array | null,
    code: string,
    newPassword: string,
    guard: Guard,
  ): Promise<void> {
    this.checkNewPassword(newPassword);
    let s: VaultSession;
    try {
      s = this.c().VaultSession.openWithRecovery(bytes, code);
    } catch (e) {
      throw this.unlockError(e, 'wrongRecovery');
    }
    try {
      const key = await this.derive(newPassword, s.beginPasswordChange(), guard);
      try {
        s.changePasswordWithRecovery(code, key);
      } finally {
        key.fill(0);
      }
      const sealed = s.sealProtected();
      const next = sealed.bytes;
      const revision = sealed.revision;
      sealed.free();
      this.active = 'protected';
      await this.protStore.compareAndSwap(expected, this.record(next), guard);
      if (this.isStale(guard)) throw new StaleWorkError(true);
      s.commit(revision);
      this.install(s, null, next);
      this.broadcast();
    } catch (e) {
      if (this.session !== s) s.free();
      throw e;
    }
  }

  /** Reset the stored vault's password with its recovery code. */
  resetPassword(code: string, newPassword: string): Promise<void> {
    return this.credential(async (guard) => {
      const rec = await this.protStore.read();
      guard();
      if (!rec) throw new VaultError('noStoredVault', 'No stored vault.');
      await this.recoverInto(rec.bytes, rec.bytes, code, newPassword, guard);
    });
  }

  /**
   * Restore a password-vault backup, opened with its own password (stored
   * as is) or with its recovery code plus a new password. Allowed into empty
   * storage or over the unlocked password vault this tab last saw.
   */
  restoreProtected(
    file: File,
    credential: { password: string } | { recoveryCode: string; newPassword: string },
  ): Promise<void> {
    return this.credential(async (guard) => {
      if (this.status() === 'stale') {
        throw new ConflictError('This tab is out of date. Reload from storage before restoring.', 'staleTab');
      }
      const replacing = this.status() === 'unlocked' && this.active === 'protected';
      if (this.status() === 'unlocked' && !replacing) {
        throw new VaultError('restoreNotAllowed', 'Lock the demo vault before restoring a password vault.');
      }
      const current = await this.protStore.read();
      guard();
      if (current && !replacing) {
        throw new VaultError('restoreNotAllowed', 'Unlock the stored password vault before replacing it.');
      }
      const expected = replacing ? this.protSnap : null;
      if (file.size > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
      const bytes = new Uint8Array(await file.arrayBuffer());
      guard();
      if (bytes.length > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
      const version = this.envelopeVersion(bytes);
      if (version === 1) throw new VaultError('demoBackup', 'This is a demo backup.');
      if (version !== 2) throw new VaultError('backupRejected', 'Not a Keymesh backup.');
      if ('recoveryCode' in credential) {
        await this.recoverInto(bytes, expected, credential.recoveryCode, credential.newPassword, guard);
        return;
      }
      const key = await this.derive(credential.password, this.c().passwordRequest(bytes), guard);
      let s: VaultSession;
      try {
        s = this.c().VaultSession.openWithPasswordKey(bytes, key);
      } catch (e) {
        throw this.unlockError(e, 'wrongPassword');
      } finally {
        key.fill(0);
      }
      try {
        this.active = 'protected';
        await this.protStore.compareAndSwap(expected, this.record(bytes), guard);
        if (this.isStale(guard)) throw new StaleWorkError(true);
      } catch (e) {
        s.free();
        if (e instanceof ConflictError && replacing && !this.isStale(guard)) this.status.set('stale');
        throw e;
      }
      this.install(s, null, bytes);
      this.broadcast();
    });
  }

  /**
   * Persist a credential change made in `s` (CAS against the snapshot). On
   * any failure the core rolls back to the stored slots, so memory and
   * storage keep the old password / recovery code.
   */
  private async persistCredentialChange(s: VaultSession, guard: Guard): Promise<void> {
    const expected = this.protSnap;
    let bytes: Uint8Array;
    let revision: number;
    try {
      const sealed = s.sealProtected();
      bytes = sealed.bytes;
      revision = sealed.revision;
      sealed.free();
    } catch (e) {
      s.rollback();
      throw e;
    }
    try {
      await this.protStore.compareAndSwap(expected, this.record(bytes), guard);
    } catch (e) {
      if (!this.isStale(guard)) {
        s.rollback();
        if (e instanceof ConflictError) this.status.set('stale');
      }
      throw e;
    }
    if (this.isStale(guard)) throw new StaleWorkError(true);
    s.commit(revision);
    this.protSnap = bytes;
    this.revision.set(revision);
    this.protectedStored.set(this.info(bytes));
    this.refreshStoredQuickUnlock(bytes);
    this.broadcast();
  }

  private protectedSession(): VaultSession {
    const s = this.s();
    if (this.active !== 'protected') throw new VaultError('demoBackup', 'This is a demo vault.');
    if (this.status() === 'stale') throw new ConflictError();
    return s;
  }

  /**
   * Change the master password. The core verifies `current` by unwrapping
   * the password slot; only a key derived for the parameters it issued is
   * accepted. Earlier backups keep the old password.
   */
  changePassword(current: string, next: string): Promise<void> {
    return this.credential(async (guard) => {
      const s = this.protectedSession();
      this.checkNewPassword(next);
      const curReq = s.currentPasswordRequest();
      const curKey = await this.derive(current, curReq, guard);
      try {
        const newKey = await this.derive(next, s.beginPasswordChange(), guard);
        try {
          s.changePasswordWithKey(curKey, newKey);
        } catch (e) {
          throw this.unlockError(e, 'wrongPassword');
        } finally {
          newKey.fill(0);
        }
      } finally {
        curKey.fill(0);
      }
      await this.persistCredentialChange(s, guard);
    });
  }

  /**
   * Start replacing the recovery code (needs the current password). Returns
   * the new code to show; nothing changes until `finishRecoveryChange`.
   */
  beginRecoveryChange(current: string): Promise<string> {
    return this.credential(async (guard) => {
      const s = this.protectedSession();
      const key = await this.derive(current, s.currentPasswordRequest(), guard);
      try {
        s.beginRecoveryChange(key);
      } catch (e) {
        throw this.unlockError(e, 'wrongPassword');
      } finally {
        key.fill(0);
      }
      return s.shownRecoveryCode();
    });
  }

  /** Confirm the new recovery code (typed back) and store it. */
  finishRecoveryChange(code: string): Promise<void> {
    return this.run(async (guard) => {
      this.requireSecure();
      const s = this.protectedSession();
      s.finishRecoveryChange(code);
      await this.persistCredentialChange(s, guard);
    });
  }

  cancelRecoveryChange(): void {
    if (this.session && this.status() === 'unlocked' && this.active === 'protected') {
      this.session.cancelRecoveryChange();
    }
  }

  // --- data-key rotation (M5 B, ADR 0002 §8) --------------------------------

  /**
   * Step 1 of a compromise rotation: prove the current password, derive the
   * new one, and let the core prepare a new data key with new password and
   * recovery slots. Returns the new recovery code to show. Nothing changes
   * (memory or storage) until `finishRotation` gets the code back.
   */
  beginRotation(current: string, next: string, revokeQuickUnlock = false): Promise<string> {
    return this.credential(async (guard) => {
      const s = this.protectedSession();
      this.checkNewPassword(next);
      if (current.normalize('NFC') === next.normalize('NFC')) {
        throw new VaultError('samePassword', 'Rotation needs a new password.');
      }
      const curKey = await this.derive(current, s.currentPasswordRequest(), guard);
      try {
        const newKey = await this.derive(next, s.beginPasswordChange(), guard);
        try {
          if (revokeQuickUnlock) s.beginRotationRevokingQuickUnlock(curKey, newKey);
          else if (JSON.parse(s.prfSlots()).length > 0) {
            throw new VaultError('quickUnlockRevokeRequired', 'Rotation revokes quick-unlock passkeys; confirm first.');
          } else s.beginRotation(curKey, newKey);
        } catch (e) {
          throw this.unlockError(e, 'wrongPassword');
        } finally {
          newKey.fill(0);
        }
      } finally {
        curKey.fill(0);
      }
      return s.shownRecoveryCode();
    });
  }

  /**
   * Step 2: the core checks the typed code, switches the session to the
   * rotated vault, and the result is stored with an exact-byte CAS
   * (requesting strict durability, a browser hint, not a guarantee).
   * Outcomes:
   * * before the write (seal error, lock, CAS mismatch): rolled back,
   *   storage keeps the old data key and credentials;
   * * the write failed some other way: the store only rejects once its
   *   transaction is over, so storage is then read back and compared byte
   *   for byte: new bytes = committed; old bytes = not committed (rolled
   *   back); other bytes = another writer (conflict, tab goes stale); read
   *   failed = unknown: the vault is LOCKED and the user unlocks again
   *   (nothing is rolled back or reinstalled on a guess);
   * * stored, but the vault was locked meanwhile: `rotatedWhileLocked` (the
   *   NEW password and code are now required). A lock always wins.
   * A mistyped code keeps the rotation pending.
   */
  finishRotation(code: string): Promise<void> {
    const seq = ++this.opSeq;
    return this.run(async (guard) => {
      this.requireSecure();
      const s = this.protectedSession();
      s.finishRotation(code);
      const expected = this.protSnap;
      let bytes: Uint8Array;
      let revision: number;
      try {
        const sealed = s.sealProtected();
        bytes = sealed.bytes;
        revision = sealed.revision;
        sealed.free();
      } catch (e) {
        s.rollback();
        throw e;
      }
      try {
        await this.protStore.compareAndSwap(expected, this.record(bytes), guard, 'strict');
      } catch (e) {
        if (e instanceof ConflictError) {
          if (!this.isStale(guard)) {
            s.rollback();
            this.status.set('stale');
          }
          throw e;
        }
        if (e instanceof StaleWorkError) {
          // The guard stopped the write before it was issued: nothing stored.
          if (!this.isStale(guard)) s.rollback();
          throw e;
        }
        const outcome = await this.storedOutcome(bytes, expected);
        if (outcome === 'old') {
          if (!this.isStale(guard)) s.rollback();
          throw e;
        }
        if (outcome === 'other') {
          if (!this.isStale(guard)) {
            s.rollback();
            this.status.set('stale');
          }
          throw new ConflictError();
        }
        if (outcome === 'unknown') {
          // Neither credential set can be assumed: drop the session, and
          // leave the locked screen a notice (the Backup view is gone now).
          this.recordNotice('rotationUncertain', seq);
          if (!this.isStale(guard)) this.lock();
          throw new VaultError('rotationUncertain', 'Could not confirm the rotation.');
        }
        // Stored after all: fall through and install.
      }
      if (this.isStale(guard)) {
        this.protSnap = bytes;
        this.protectedStored.set(this.info(bytes));
      this.refreshStoredQuickUnlock(bytes);
        this.refreshStoredQuickUnlock(bytes);
    this.refreshStoredQuickUnlock(bytes);
        this.broadcast();
        this.recordNotice('rotatedWhileLocked', seq);
        throw new VaultError('rotatedWhileLocked', 'The rotation was stored before the vault was locked.');
      }
      s.commit(revision);
      this.protSnap = bytes;
      this.revision.set(revision);
      this.protectedStored.set(this.info(bytes));
      this.refreshStoredQuickUnlock(bytes);
    this.refreshStoredQuickUnlock(bytes);
      this.version.update((v) => v + 1);
      this.broadcast();
    });
  }

  /** Which envelope storage holds now, compared byte for byte. */
  private async storedOutcome(next: Uint8Array, previous: Uint8Array | null): Promise<'new' | 'old' | 'other' | 'unknown'> {
    try {
      const now = await this.protStore.read();
      if (now && sameBytes(now.bytes, next)) return 'new';
      if (now ? sameBytes(now.bytes, previous) : previous === null) return 'old';
      return 'other';
    } catch {
      return 'unknown';
    }
  }

  cancelRotation(): void {
    if (this.session && this.status() === 'unlocked' && this.active === 'protected') {
      this.session.cancelRotation();
    }
  }

  // --- quick unlock: WebAuthn PRF passkeys (M5 C1, ADR 0003 §4.1) ----------

  /** Quick-unlock passkeys of the STORED password vault (public data). */
  readonly storedQuickUnlock = signal<PrfSlotInfo[]>([]);
  /** In-flight WebAuthn ceremony; aborted on lock. */
  private webauthnAbort: AbortController | null = null;

  quickUnlockSupported(): boolean {
    return this.secure && this.webauthn.available();
  }

  private refreshStoredQuickUnlock(bytes: Uint8Array | null): void {
    try {
      this.storedQuickUnlock.set(bytes && this.core ? (JSON.parse(this.c().prfRequest(bytes)) as PrfSlotInfo[]) : []);
    } catch {
      this.storedQuickUnlock.set([]);
    }
  }

  /** Passkeys enrolled in the open password vault. */
  quickUnlockSlots(): PrfSlotInfo[] {
    if (this.active !== 'protected' || this.status() !== 'unlocked') return [];
    return JSON.parse(this.s().prfSlots()) as PrfSlotInfo[];
  }

  private rpId(): string {
    return location.hostname;
  }

  private async ceremony<T>(guard: Guard, run: (signal: AbortSignal) => Promise<T>): Promise<T> {
    const ac = new AbortController();
    this.webauthnAbort = ac;
    try {
      const r = await run(ac.signal);
      if (this.isStale(guard)) throw new StaleWorkError();
      return r;
    } catch (e) {
      if (this.isStale(guard)) throw new StaleWorkError();
      throw e;
    } finally {
      if (this.webauthnAbort === ac) this.webauthnAbort = null;
    }
  }

  /** Unlock the stored password vault with an enrolled passkey. */
  unlockWithQuickUnlock(): Promise<void> {
    return this.credential(async (guard) => {
      if (!this.webauthn.available()) throw new VaultError('quickUnlockUnsupported', 'Passkeys are not available here.');
      const rec = await this.protStore.read();
      guard();
      if (!rec) throw new VaultError('noStoredVault', 'No stored vault.');
      const slots = JSON.parse(this.c().prfRequest(rec.bytes)) as PrfSlotInfo[];
      const rp = this.rpId();
      const mine = slots.filter((x) => x.rp_id === rp);
      if (mine.length === 0) throw new VaultError('quickUnlockNone', 'No passkey is set up for this vault here.');
      const evalByCredential: Record<string, { first: Uint8Array<ArrayBuffer> }> = {};
      for (const x of mine) evalByCredential[x.credential_id] = { first: b64u.decode(x.salt) };
      const cred = (await this.ceremony(guard, (signal) =>
        this.webauthn.get({
          signal,
          publicKey: {
            challenge: randomBytes(32), // no server: not verified, only required by the API
            rpId: rp,
            allowCredentials: mine.map((x) => ({ type: 'public-key' as const, id: b64u.decode(x.credential_id) })),
            userVerification: 'required',
            timeout: 120_000,
            extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
          },
        }),
      )) as PublicKeyCredential | null;
      if (!cred) throw new VaultError('quickUnlockFailed', 'The passkey did not unlock this vault.');
      const prf = prfFirst(cred);
      const authData = new Uint8Array((cred.response as AuthenticatorAssertionResponse).authenticatorData);
      if (!prf) throw new VaultError('quickUnlockFailed', 'The passkey did not unlock this vault.');
      let s: VaultSession;
      try {
        s = this.c().VaultSession.openWithPrf(rec.bytes, new Uint8Array(cred.rawId), authData, prf, rp);
      } catch {
        throw new VaultError('quickUnlockFailed', 'The passkey did not unlock this vault.');
      } finally {
        prf.fill(0);
      }
      this.active = 'protected';
      this.protSnap = rec.bytes;
      this.install(s, null, rec.bytes);
    });
  }

  /**
   * Enrol a passkey for quick unlock (sensitive: needs the master password).
   * Order: KDF for the password → core issues {slot_id, salt} → create()
   * with PRF → (get() if no PRF result at creation) → core adds and verifies
   * the slot → exact-byte CAS. A failure after create() means the
   * authenticator holds a credential Keymesh cannot delete: reported as
   * `quickUnlockOrphan` (before the write) so the user can remove it.
   */
  enrollQuickUnlock(current: string, label: string): Promise<void> {
    const seq = ++this.opSeq;
    return this.credential(async (guard) => {
      const s = this.protectedSession();
      if (!this.webauthn.available()) throw new VaultError('quickUnlockUnsupported', 'Passkeys are not available here.');
      if ((await this.webauthn.prfHint()) === false) {
        throw new VaultError('quickUnlockUnsupported', 'This browser cannot use passkeys to unlock vaults.');
      }
      guard();
      const curKey = await this.derive(current, s.currentPasswordRequest(), guard);
      // From create() on, the authenticator may hold a credential Keymesh
      // cannot delete. Its non-secret metadata goes into a notice that
      // survives the lock (the locked screen shows it).
      const meta = { label: label || 'Keymesh', at: Date.now() };
      let created: PublicKeyCredential | null = null;
      const orphan = (): never => {
        this.recordNotice('quickUnlockOrphan', seq, { passkey: meta });
        throw new VaultError('quickUnlockOrphan', 'The passkey was created but not added to this vault.');
      };
      try {
        let e: { slot_id: string; salt: string; vault_id: string };
        try {
          e = JSON.parse(s.beginPrfEnrolment(curKey)) as typeof e; // checks the password first
        } catch (err) {
          throw this.unlockError(err, 'wrongPassword'); // no passkey created
        }
        const salt = b64u.decode(e.salt);
        const rp = this.rpId();
        let prf: Uint8Array | null = null;
        let createStarted = false;
        try {
          createStarted = true;
          created = (await this.ceremony(guard, (signal) =>
            this.webauthn.create({
              signal,
              publicKey: {
                challenge: randomBytes(32),
                rp: { id: rp, name: 'Keymesh' },
                user: { id: randomBytes(16), name: `Keymesh vault ${e.vault_id.slice(0, 8)}`, displayName: meta.label },
                pubKeyCredParams: [
                  { type: 'public-key', alg: -7 },
                  { type: 'public-key', alg: -8 },
                  { type: 'public-key', alg: -257 },
                ],
                authenticatorSelection: { userVerification: 'required', residentKey: 'preferred' },
                timeout: 120_000,
                extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
              },
            }),
          )) as PublicKeyCredential | null;
          if (!created) throw new VaultError('quickUnlockUnsupported', 'No passkey was created.');
          if (!prfEnabled(created)) orphan();
          let flags = flagsOf((created.response as AuthenticatorAttestationResponse).getAuthenticatorData());
          prf = prfFirst(created);
          if (!prf) {
            // Some authenticators evaluate PRF only on assertion.
            const id = new Uint8Array(created.rawId);
            const a = (await this.ceremony(guard, (signal) =>
              this.webauthn.get({
                signal,
                publicKey: {
                  challenge: randomBytes(32),
                  rpId: rp,
                  allowCredentials: [{ type: 'public-key', id }],
                  userVerification: 'required',
                  extensions: { prf: { evalByCredential: { [b64u.encode(id)]: { first: salt } } } } as AuthenticationExtensionsClientInputs,
                },
              }),
            )) as PublicKeyCredential | null;
            prf = a ? prfFirst(a) : null;
            if (a) flags = flagsOf((a.response as AuthenticatorAssertionResponse).authenticatorData);
          }
          if (!prf || !(flags & FLAG_UV)) orphan();
          s.finishPrfEnrolment(curKey, new Uint8Array(created.rawId), rp, (flags & FLAG_BE) !== 0, meta.label, prf!);
        } catch (err) {
          s.cancelPrfEnrolment();
          // A credential exists if create() returned one; it MAY exist if a
          // lock aborted the ceremony after it started. A user cancelling
          // (NotAllowedError) means no credential was made.
          const alreadyReported = err instanceof VaultError && err.code === 'quickUnlockOrphan';
          if (!alreadyReported && (created || (createStarted && err instanceof StaleWorkError))) orphan();
          if (err instanceof DOMException && err.name === 'NotAllowedError') {
            throw new VaultError('quickUnlockFailed', 'The passkey request was cancelled.');
          }
          throw err;
        } finally {
          prf?.fill(0);
        }
      } finally {
        curKey.fill(0);
      }
      await this.persistEnrolment(s, guard, seq, meta, b64u.encode(new Uint8Array(created!.rawId)));
    });
  }

  /**
   * Store an enrolment with an exact-byte CAS and settled-outcome
   * reconciliation (as for rotation): only an outcome PROVEN not written is
   * an orphan; an unknown one stays pending (no delete advice) until a
   * later successful unlock compares the stored slots.
   */
  private async persistEnrolment(
    s: VaultSession,
    guard: Guard,
    seq: number,
    meta: { label: string; at: number },
    credentialId: string,
  ): Promise<void> {
    const orphan = (): never => {
      this.recordNotice('quickUnlockOrphan', seq, { passkey: meta });
      throw new VaultError('quickUnlockOrphan', 'The passkey was created but not added to this vault.');
    };
    const expected = this.protSnap;
    let bytes: Uint8Array;
    let revision: number;
    try {
      const sealed = s.sealProtected();
      bytes = sealed.bytes;
      revision = sealed.revision;
      sealed.free();
    } catch {
      s.rollback();
      return orphan();
    }
    try {
      await this.protStore.compareAndSwap(expected, this.record(bytes), guard);
    } catch (err) {
      if (err instanceof ConflictError) {
        if (!this.isStale(guard)) {
          s.rollback();
          this.status.set('stale');
        }
        return orphan(); // CAS refused: not written
      }
      if (err instanceof StaleWorkError) {
        if (!this.isStale(guard)) s.rollback();
        return orphan(); // stopped before put: not written
      }
      const outcome = await this.storedOutcome(bytes, expected);
      if (outcome === 'old') {
        if (!this.isStale(guard)) s.rollback();
        return orphan();
      }
      if (outcome !== 'new') {
        this.recordNotice('quickUnlockUncertain', seq, { passkey: meta, credentialId });
        if (!this.isStale(guard)) this.lock();
        throw new VaultError('quickUnlockUncertain', 'Could not confirm whether the passkey was added.');
      }
    }
    if (this.isStale(guard)) {
      this.protSnap = bytes;
      this.protectedStored.set(this.info(bytes));
      this.refreshStoredQuickUnlock(bytes);
      this.broadcast();
      this.recordNotice('quickUnlockSavedWhileLocked', seq, { passkey: meta });
      throw new StaleWorkError(true);
    }
    s.commit(revision);
    this.protSnap = bytes;
    this.revision.set(revision);
    this.protectedStored.set(this.info(bytes));
    this.refreshStoredQuickUnlock(bytes);
    this.version.update((v) => v + 1);
    this.broadcast();
  }

  /** Remove a passkey from this vault (needs the master password). */
  removeQuickUnlock(current: string, slotId: string): Promise<void> {
    return this.credential(async (guard) => {
      const s = this.protectedSession();
      const key = await this.derive(current, s.currentPasswordRequest(), guard);
      try {
        s.removePrfSlot(key, slotId);
      } catch (e) {
        throw this.unlockError(e, 'wrongPassword');
      } finally {
        key.fill(0);
      }
      await this.persistCredentialChange(s, guard);
    });
  }

  /** Delete the stored password vault (only the exact one this tab last saw). */
  discardProtected(): Promise<void> {
    this.lock();
    const expected = this.protSnap;
    return this.run(async (guard) => {
      this.requireSecure();
      await this.protStore.compareAndClear(expected, guard);
      guard();
      this.protSnap = null;
      this.protectedStored.set(null);
      this.storedQuickUnlock.set([]);
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

  /** Password from user settings, generated by the core (not kept there). */
  generatePasswordWith(options: PasswordOptions): string {
    if (this.status() !== 'unlocked') throw new LockedError();
    return this.c().generatePasswordWithOptions(JSON.stringify(options));
  }

  // --- Ed25519 sign / verify, passphrases (M5 B) ----------------------------

  /** Sign the exact bytes of `message` with Ed25519 item `id` (unlocked only). */
  signEd25519(id: string, message: string, encoding: MessageEncoding): SignatureOut {
    if (this.status() !== 'unlocked') throw new LockedError();
    return JSON.parse(this.s().signEd25519(id, message, encoding)) as SignatureOut;
  }

  /** Strict verification in the core; needs no vault. */
  verifyEd25519(publicKey: string, message: string, encoding: MessageEncoding, signature: string): Verdict {
    return this.c().verifyEd25519(publicKey, message, encoding, signature) as Verdict;
  }

  /** Byte count and hex of exactly what would be signed or verified. */
  messagePreview(message: string, encoding: MessageEncoding): MessagePreview {
    return JSON.parse(this.c().messagePreview(message, encoding)) as MessagePreview;
  }

  /** Passphrase from the core (EFF Long Wordlist, OS CSPRNG). */
  generatePassphrase(options: PassphraseOptions): string {
    return this.c().generatePassphrase(JSON.stringify(options));
  }

  passphraseSummary(options: PassphraseOptions): PassphraseSummary {
    return JSON.parse(this.c().passphraseSummary(JSON.stringify(options))) as PassphraseSummary;
  }

  /** Validate settings in the core without generating anything. */
  checkPasswordOptions(options: PasswordOptions): void {
    this.c().passwordPolicySummary(JSON.stringify(options));
  }

  /**
   * Generate a password the core keeps as the current preview, so that
   * `savePreview` stores exactly this value (and only once).
   */
  previewPassword(options: PasswordOptions): string {
    if (this.status() !== 'unlocked') throw new LockedError();
    return this.s().previewPassword(JSON.stringify(options));
  }

  previewSecret(bytes: number, encoding: string): string {
    if (this.status() !== 'unlocked') throw new LockedError();
    return this.s().previewSecret(bytes, encoding);
  }

  /**
   * Store the shown preview as a generated Secret item. The core refuses a
   * value that is not its current preview (replaced, discarded on lock, or
   * already saved), so nothing else can be stored in its place.
   */
  /** Passphrase preview (EFF Long Wordlist), kept by the core like the others. */
  previewPassphrase(options: PassphraseOptions): string {
    if (this.status() !== 'unlocked') throw new LockedError();
    return this.s().previewPassphrase(JSON.stringify(options));
  }

  savePreview(kind: 'password' | 'passphrase' | 'secret', shown: string, title: string): Promise<string> {
    return this.mutate((s) => s.savePreview(kind, shown, title, ''));
  }

  /** Forget previews held by the core (generator view closed). */
  discardPreviews(): void {
    if (this.session && this.status() !== 'locked') this.session.discardPreviews();
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
      const key = this.active === 'protected' ? null : this.key;
      const expected = this.snapshot;
      const result = fn(s);
      let bytes: Uint8Array;
      let revision: number;
      try {
        const sealed = key ? s.seal(key) : s.sealProtected();
        bytes = sealed.bytes;
        revision = sealed.revision;
        sealed.free();
      } catch (e) {
        this.version.update((v) => v + 1);
        this.refreshList();
        throw e;
      }
      try {
        await this.store.compareAndSwap(expected, this.record(bytes), guard);
      } catch (e) {
        // Cancelled before the write (lock): storage unchanged, nothing to mark.
        if (!(e instanceof StaleWorkError) && !this.isStale(guard)) this.status.set('stale');
        throw e;
      }
      // Locked after the write committed: the ciphertext is stored (unlock
      // re-reads it), but the freed session is never touched again.
      if (this.isStale(guard)) throw new StaleWorkError(true);
      s.commit(revision);
      this.snapshot = bytes;
      this.revision.set(revision);
      this.setStoredInfo(bytes);
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
      if (status === 'unlocked' && this.active === 'protected') {
        throw new VaultError('demoBackup', 'A demo backup cannot replace a password vault.');
      }
      this.active = 'demo';
      if (file.size > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
      const expected = status === 'unlocked' ? this.snapshot : null;
      const bytes = new Uint8Array(await file.arrayBuffer());
      guard();
      if (bytes.length > this.maxBytes()) throw new VaultError('backupTooLarge', 'Backup file is too large.');
      if (this.envelopeVersion(bytes) === 2) {
        throw new VaultError('protectedBackup', 'This backup belongs to a password vault.');
      }
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
        await this.store.compareAndSwap(expected, this.record(bytes), guard);
      } catch (e) {
        drop();
        if (e instanceof ConflictError && !this.isStale(guard) && status === 'unlocked') {
          this.status.set('stale');
        }
        throw e;
      }
      if (this.isStale(guard)) {
        // Lock won after the (already verified) backup was written:
        // nothing is installed; unlocking later reads the stored envelope.
        drop();
        throw new StaleWorkError(true);
      }
      this.install(candidate, key, bytes);
      this.broadcast();
    });
  }

  /**
   * Re-read storage after a conflict; unsaved in-memory changes are dropped.
   * The vault keeps its identity: a demo vault is reopened with its key, a
   * password vault is locked and its current stored copy re-read, so the
   * user unlocks it again with a credential. A password-vault conflict never
   * opens (or touches) the demo vault.
   */
  async reload(): Promise<void> {
    const wasProtected = this.active === 'protected';
    this.lock();
    if (!wasProtected) {
      await this.openStored();
      return;
    }
    this.protectedReloaded.set(true);
    await this.run(async (guard) => {
      this.requireSecure();
      const rec = await this.protStore.read();
      guard();
      this.protSnap = rec?.bytes ?? null;
      this.protectedStored.set(rec ? this.info(rec.bytes) : null);
      this.refreshStoredQuickUnlock(rec?.bytes ?? null);
    });
  }
}
