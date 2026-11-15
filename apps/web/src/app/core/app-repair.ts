import { Injectable } from '@angular/core';

export type RepairResult =
  /** Own caches removed and worker unregistered; reload to fetch fresh files. */
  | 'repaired'
  /** The server cannot be reached: nothing was changed. */
  | 'offline'
  /** The server answered, but not with this app's file list: nothing was changed. */
  | 'unavailable';

/** Seams for tests; production uses the browser's own objects. */
export interface RepairEnv {
  fetch: typeof fetch;
  caches: Pick<CacheStorage, 'keys' | 'delete'>;
  serviceWorker: Pick<ServiceWorkerContainer, 'getRegistrations'> | undefined;
  baseHref: string;
}

/**
 * Repair the installed app's OWN static files (Angular service worker caches),
 * for when a cached file is damaged and the app cannot start.
 *
 * Bounded by design:
 * * Works without the vault core or WASM (it is what may be broken).
 * * Requires the server first: the file list is fetched with `ngsw-bypass`
 *   (straight to the network). Offline or a bad answer changes nothing.
 * * Touches only this app: the service-worker registration whose scope is
 *   this app's base URL, and caches named `ngsw:<scope path>:…`.
 * * Never touches IndexedDB (vault ciphertext), localStorage (preferences),
 *   cookies or any other cache. The caller reloads afterwards, after the
 *   user confirmed; the next load downloads and verifies fresh files.
 */
@Injectable({ providedIn: 'root' })
export class AppRepair {
  env: RepairEnv = {
    fetch: (...a) => fetch(...a),
    caches: typeof caches === 'undefined' ? { keys: async () => [], delete: async () => false } : caches,
    serviceWorker: typeof navigator === 'undefined' ? undefined : navigator.serviceWorker,
    baseHref: typeof document === 'undefined' ? 'http://localhost/' : document.baseURI,
  };

  async repair(): Promise<RepairResult> {
    const { fetch: get, caches: store, serviceWorker, baseHref } = this.env;
    const base = new URL('.', baseHref);
    let res: Response;
    try {
      res = await get(new URL('ngsw.json?ngsw-bypass=true', base).href, { cache: 'no-store', credentials: 'same-origin' });
    } catch {
      return 'offline';
    }
    try {
      const manifest = (await res.json()) as { configVersion?: unknown; hashTable?: unknown };
      if (!res.ok || manifest.configVersion !== 1 || typeof manifest.hashTable !== 'object' || manifest.hashTable === null) {
        return 'unavailable';
      }
    } catch {
      return 'unavailable';
    }
    for (const reg of (await serviceWorker?.getRegistrations()) ?? []) {
      if (reg.scope === base.href) await reg.unregister();
    }
    const prefix = `ngsw:${base.pathname}:`;
    for (const name of await store.keys()) {
      if (name.startsWith(prefix)) await store.delete(name);
    }
    return 'repaired';
  }
}
