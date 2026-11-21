import { IDBFactory } from 'fake-indexeddb';
import { ConflictError, StoredVault, VaultStore } from './vault-store';

function rec(revision: number, vaultId = 'v1', fill = revision): StoredVault {
  return { bytes: new Uint8Array([fill, revision]), vaultId, kekId: 'k', revision };
}

describe('VaultStore (encrypted envelope only, exact-snapshot compare-and-swap)', () => {
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

  it('compareAndSwap writes only when the stored bytes equal the expected snapshot', async () => {
    const r1 = rec(1);
    await store.create(r1);
    await store.compareAndSwap(r1.bytes, rec(2));
    // A stale writer still holding r1 is rejected and changes nothing.
    await expect(store.compareAndSwap(r1.bytes, rec(2, 'v1', 99))).rejects.toBeInstanceOf(ConflictError);
    const cur = await store.read();
    expect(Array.from(cur!.bytes)).toEqual([2, 2]);
  });

  it('same revision with different content is still a conflict (restore can reuse revisions)', async () => {
    const seenByStaleTab = rec(2, 'v1', 10);
    await store.create(seenByStaleTab);
    // Another tab restores an older backup and edits again: revision 2 again, other bytes.
    await store.compareAndSwap(seenByStaleTab.bytes, rec(1, 'v1', 20));
    const other = await store.read();
    await store.compareAndSwap(other!.bytes, rec(2, 'v1', 30));
    await expect(store.compareAndSwap(seenByStaleTab.bytes, rec(3, 'v1', 40))).rejects.toBeInstanceOf(
      ConflictError,
    );
    expect(Array.from((await store.read())!.bytes)).toEqual([30, 2]);
  });

  it('expected null means storage must still be empty (initial restore)', async () => {
    await store.compareAndSwap(null, rec(5));
    expect((await store.read())?.revision).toBe(5);
    await expect(store.compareAndSwap(null, rec(6))).rejects.toBeInstanceOf(ConflictError);
    expect((await store.read())?.revision).toBe(5);
  });

  it('a snapshot never matches an empty store', async () => {
    await expect(store.compareAndSwap(rec(1).bytes, rec(2))).rejects.toBeInstanceOf(ConflictError);
    expect(await store.read()).toBeNull();
  });

  it('clear', async () => {
    await store.create(rec(1));
    await store.clear();
    expect(await store.read()).toBeNull();
  });
});
