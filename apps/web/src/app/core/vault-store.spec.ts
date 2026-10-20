import { IDBFactory } from 'fake-indexeddb';
import { ConflictError, StoredVault, VaultStore } from './vault-store';

function rec(revision: number, vaultId = 'v1', fill = revision): StoredVault {
  return { bytes: new Uint8Array([fill]), vaultId, kekId: 'k', revision };
}

describe('VaultStore (encrypted envelope only, compare-and-swap)', () => {
  let store: VaultStore;
  beforeEach(() => {
    store = new VaultStore(new IDBFactory());
  });

  it('create refuses to replace an existing vault', async () => {
    expect(await store.read()).toBeNull();
    await store.create(rec(1));
    await expect(store.create(rec(1, 'other'))).rejects.toBeInstanceOf(ConflictError);
    expect((await store.read())?.vaultId).toBe('v1');
  });

  it('compareAndPut writes only on the expected revision of the same vault', async () => {
    await store.create(rec(1));
    await store.compareAndPut(1, rec(2));
    // A stale writer (still at revision 1) is rejected and changes nothing.
    await expect(store.compareAndPut(1, rec(2, 'v1', 99))).rejects.toBeInstanceOf(ConflictError);
    // A different vault id is rejected.
    await expect(store.compareAndPut(2, rec(3, 'v2'))).rejects.toBeInstanceOf(ConflictError);
    const cur = await store.read();
    expect(cur?.revision).toBe(2);
    expect(Array.from(cur!.bytes)).toEqual([2]);
  });

  it('compareAndPut on an empty store is a conflict', async () => {
    await expect(store.compareAndPut(0, rec(1))).rejects.toBeInstanceOf(ConflictError);
    expect(await store.read()).toBeNull();
  });

  it('replace and clear', async () => {
    await store.create(rec(1));
    await store.replace(rec(7, 'v9'));
    expect((await store.read())?.vaultId).toBe('v9');
    await store.clear();
    expect(await store.read()).toBeNull();
  });
});
