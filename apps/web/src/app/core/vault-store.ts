/**
 * IndexedDB persistence of the *encrypted* vault envelope only.
 *
 * One record (key `primary`) holds the envelope bytes and its public header
 * fields (vault id, key id, revision). No plaintext, no key material and no
 * search index is ever stored.
 *
 * Writers use compare-and-swap inside a single readwrite transaction:
 * a save succeeds only if the stored revision still equals the revision the
 * writer loaded, so a second tab can never silently clobber newer data.
 */

export interface StoredVault {
  bytes: Uint8Array;
  vaultId: string;
  kekId: string;
  revision: number;
}

export class ConflictError extends Error {
  constructor(message = 'The vault was changed elsewhere (another tab?). Reload it to continue.') {
    super(message);
    this.name = 'ConflictError';
  }
}

const KEY = 'primary';

function req<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error ?? new Error('IndexedDB request failed'));
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onabort = () => reject(tx.error ?? new ConflictError());
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
  });
}

function isStored(v: unknown): v is StoredVault {
  const r = v as StoredVault | undefined;
  return (
    !!r &&
    // Realm-independent check (structured clone may come from another realm).
    Object.prototype.toString.call(r.bytes) === '[object Uint8Array]' &&
    typeof r.vaultId === 'string' &&
    typeof r.kekId === 'string' &&
    typeof r.revision === 'number'
  );
}

export class VaultStore {
  private db: Promise<IDBDatabase> | null = null;

  constructor(
    private readonly factory: IDBFactory,
    private readonly name = 'keymesh-demo',
  ) {}

  private open(): Promise<IDBDatabase> {
    this.db ??= new Promise((resolve, reject) => {
      const r = this.factory.open(this.name, 1);
      r.onupgradeneeded = () => r.result.createObjectStore('vault');
      r.onsuccess = () => resolve(r.result);
      r.onerror = () => reject(r.error ?? new Error('cannot open IndexedDB'));
    });
    return this.db;
  }

  async read(): Promise<StoredVault | null> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readonly');
    const v = await req(tx.objectStore('vault').get(KEY));
    if (v === undefined) return null;
    if (!isStored(v)) throw new Error('stored vault record is malformed');
    return v;
  }

  /** First save of a new vault. Never replaces an existing record. */
  async create(v: StoredVault): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    const os = tx.objectStore('vault');
    const existing = await req(os.get(KEY));
    if (existing !== undefined) {
      tx.abort();
      throw new ConflictError('A stored demo vault already exists. Discard it first.');
    }
    os.add(v, KEY);
    await done(tx);
  }

  /**
   * Replace the record only if it still holds `expectedRevision` of the same
   * vault. Otherwise nothing is written and ConflictError is thrown.
   */
  async compareAndPut(expectedRevision: number, v: StoredVault): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    const os = tx.objectStore('vault');
    const cur = await req(os.get(KEY));
    if (!isStored(cur) || cur.vaultId !== v.vaultId || cur.revision !== expectedRevision) {
      tx.abort();
      throw new ConflictError();
    }
    os.put(v, KEY);
    await done(tx);
  }

  /** Unconditional replace — only after the caller verified `v` decrypts. */
  async replace(v: StoredVault): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    tx.objectStore('vault').put(v, KEY);
    await done(tx);
  }

  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    tx.objectStore('vault').delete(KEY);
    await done(tx);
  }
}
