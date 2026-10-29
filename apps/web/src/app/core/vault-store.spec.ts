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
  describe('cancellation before the write (lock wins while still cancellable)', () => {
    class Cancelled extends Error {}
    /** Throws on its `n`-th check: 1 = after open, 2 = after reading the current record. */
    const cancelAt = (n: number) => {
      let calls = 0;
      return {
        guard: () => {
          if (++calls === n) throw new Cancelled();
        },
        calls: () => calls,
      };
    };

    for (const [n, where] of [[1, 'after the database opens'], [2, 'after reading the current record']] as const) {
      it(`compareAndSwap cancelled ${where} writes nothing and aborts cleanly`, async () => {
        const r1 = rec(1);
        await store.create(r1);
        const g = cancelAt(n);
        await expect(store.compareAndSwap(r1.bytes, rec(2), g.guard)).rejects.toBeInstanceOf(Cancelled);
        expect(g.calls()).toBe(n);
        expect(Array.from((await store.read())!.bytes)).toEqual([1, 1]);
        // The aborted transaction left storage usable.
        await store.compareAndSwap(r1.bytes, rec(2));
        expect((await store.read())?.revision).toBe(2);
      });

      it(`compareAndClear cancelled ${where} deletes nothing`, async () => {
        const r1 = rec(1);
        await store.create(r1);
        await expect(store.compareAndClear(r1.bytes, cancelAt(n).guard)).rejects.toBeInstanceOf(Cancelled);
        expect((await store.read())?.revision).toBe(1);
      });
    }

    it('a passing guard is checked after open and after the read, then writes', async () => {
      const g = cancelAt(99);
      await store.compareAndSwap(null, rec(1), g.guard);
      expect(g.calls()).toBe(2);
      expect((await store.read())?.revision).toBe(1);
    });

    it('a write held behind another transaction is cancelled once it gets its turn', async () => {
      const factory = new IDBFactory();
      store = new VaultStore(factory);
      const r1 = rec(1);
      await store.create(r1);
      // Hold the object store with another connection's readwrite transaction.
      const db = await new Promise<IDBDatabase>((resolve) => {
        const r = factory.open('keymesh-demo', 1);
        r.onsuccess = () => resolve(r.result);
      });
      let hold = true;
      const tx = db.transaction('vault', 'readwrite');
      const spin = () => {
        if (hold) tx.objectStore('vault').get('primary').onsuccess = spin;
      };
      spin();
      let cancelled = false;
      const write = store.compareAndSwap(r1.bytes, rec(2), () => {
        if (cancelled) throw new Cancelled();
      });
      await new Promise((r) => setTimeout(r, 20));
      cancelled = true; // the vault locks while the write is still waiting
      hold = false;
      await expect(write).rejects.toBeInstanceOf(Cancelled);
      expect(Array.from((await store.read())!.bytes)).toEqual([1, 1]);
      db.close();
    });

    it('a failing put aborts the transaction and leaves the record unchanged', async () => {
      const r1 = rec(1);
      await store.create(r1);
      const bad = { ...rec(2), vaultId: (() => 'x') as unknown as string }; // not cloneable
      await expect(store.compareAndSwap(r1.bytes, bad)).rejects.toBeTruthy();
      expect(Array.from((await store.read())!.bytes)).toEqual([1, 1]);
      await store.compareAndSwap(r1.bytes, rec(2));
      expect((await store.read())?.revision).toBe(2);
    });
  });
});
