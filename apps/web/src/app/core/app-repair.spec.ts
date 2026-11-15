import 'fake-indexeddb/auto';
import { TestBed } from '@angular/core/testing';
import { AppRepair, RepairEnv } from './app-repair';

function env(opts: { fetch?: () => Promise<Response>; scopes?: string[] } = {}) {
  const names = ['ngsw:/:db:control', 'ngsw:/:abc123:assets:app:cache', 'ngsw:/other/:x:cache', 'someone-else', 'ngsw:/x'];
  const deleted: string[] = [];
  const unregistered: string[] = [];
  const e: RepairEnv = {
    fetch: vi.fn(opts.fetch ?? (async () => new Response(JSON.stringify({ configVersion: 1, hashTable: {} }), { status: 200 }))),
    caches: {
      keys: async () => [...names],
      delete: async (n: string) => (deleted.push(n), true),
    },
    serviceWorker: {
      getRegistrations: async () =>
        (opts.scopes ?? ['http://app.test/', 'http://app.test/other/']).map(
          (scope) => ({ scope, unregister: async () => (unregistered.push(scope), true) }) as unknown as ServiceWorkerRegistration,
        ),
    },
    baseHref: 'http://app.test/',
  };
  TestBed.resetTestingModule();
  const r = TestBed.inject(AppRepair);
  r.env = e;
  return { r, e, deleted, unregistered };
}

describe('app file repair (static caches only)', () => {
  it('online: removes only this app scope’s caches and worker; never IndexedDB or storage', async () => {
    const del = vi.spyOn(indexedDB, 'deleteDatabase');
    const clear = vi.spyOn(Storage.prototype, 'clear');
    const remove = vi.spyOn(Storage.prototype, 'removeItem');
    const t = env();
    expect(await t.r.repair()).toBe('repaired');
    expect(t.e.fetch).toHaveBeenCalledWith('http://app.test/ngsw.json?ngsw-bypass=true', expect.objectContaining({ cache: 'no-store' }));
    expect(t.deleted.sort()).toEqual(['ngsw:/:abc123:assets:app:cache', 'ngsw:/:db:control']);
    expect(t.unregistered).toEqual(['http://app.test/']);
    expect(del).not.toHaveBeenCalled();
    expect(clear).not.toHaveBeenCalled();
    expect(remove).not.toHaveBeenCalled();
  });

  it('offline: changes nothing', async () => {
    const t = env({ fetch: async () => Promise.reject(new TypeError('Failed to fetch')) });
    expect(await t.r.repair()).toBe('offline');
    expect(t.deleted).toEqual([]);
    expect(t.unregistered).toEqual([]);
  });

  it('a server answer that is not this app’s file list changes nothing', async () => {
    for (const res of [
      new Response('<!doctype html>', { status: 200 }),
      new Response('not found', { status: 404 }),
      new Response(JSON.stringify({ configVersion: 2, hashTable: {} }), { status: 200 }),
      new Response(JSON.stringify({ configVersion: 1 }), { status: 200 }),
      new Response('{}', { status: 504 }),
    ]) {
      const t = env({ fetch: async () => res });
      expect(await t.r.repair()).toBe('unavailable');
      expect(t.deleted).toEqual([]);
      expect(t.unregistered).toEqual([]);
    }
  });
});
