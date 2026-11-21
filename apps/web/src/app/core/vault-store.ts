/**
 * IndexedDB persistence of the *encrypted* vault envelope only.
 *
 * One record (key `primary`) holds the envelope bytes and its public header
 * fields (vault id, key id, revision). No plaintext, no key material and no
 * search index is ever stored.
 *
 * Every write is a compare-and-swap inside one readwrite transaction: it
 * succeeds only if the stored envelope is exactly the snapshot the writer last
 * saw, so another tab (or an older restore) can never be silently clobbered.
 * There is no unconditional write path.
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

function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
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
    try {
      await this.compareAndSwap(null, v);
    } catch (e) {
      if (e instanceof ConflictError) {
        throw new ConflictError('A stored demo vault already exists. Discard it first.');
      }
      throw e;
    }
  }

  /**
   * Atomically replace the record only if the stored envelope is byte-for-byte
   * the snapshot this writer last saw (`null`: storage must be empty).
   * Comparing exact bytes, not revision numbers, keeps this safe when a
   * restored backup reuses an older revision. On mismatch nothing is written.
   */
  async compareAndSwap(expected: Uint8Array | null, next: StoredVault): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    const os = tx.objectStore('vault');
    const cur = await req(os.get(KEY));
    const matches =
      expected === null
        ? cur === undefined
        : isStored(cur) && sameBytes(cur.bytes, expected);
    if (!matches) {
      tx.abort();
      throw new ConflictError();
    }
    os.put(next, KEY);
    await done(tx);
  }

  /** Delete the record only if it is exactly `expected` (null: already empty). */
  async compareAndClear(expected: Uint8Array | null): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    const os = tx.objectStore('vault');
    const cur = await req(os.get(KEY));
    const matches =
      expected === null ? cur === undefined : isStored(cur) && sameBytes(cur.bytes, expected);
    if (!matches) {
      tx.abort();
      throw new ConflictError('The stored vault changed elsewhere; reload before discarding.');
    }
    if (cur !== undefined) os.delete(KEY);
    await done(tx);
  }

  /** Test helper / explicit reset. */
  async clear(): Promise<void> {
    const db = await this.open();
    const tx = db.transaction('vault', 'readwrite');
    tx.objectStore('vault').delete(KEY);
    await done(tx);
  }
}
