/**
 * Opt-in for website icons fetched by THIS app's own server (M5 C3).
 * Off by default. When on, only the item currently being VIEWED asks, and
 * only for a public host (never private/internal names): the request is
 * same-origin `/api/favicon?host=<host>` with nothing else (no title,
 * account, path or query). Existing vault hosts are never enumerated.
 * The server must also enable the route (KEYMESH_FAVICON=1); otherwise it
 * answers 404 and the local icon stays. Non-secret, stored per browser.
 */
import { Injectable, InjectionToken, inject, signal } from '@angular/core';

export const FAVICON_KEY = 'keymesh.favicon.v1';

export const FAVICON_STORAGE = new InjectionToken<Storage | null>('keymesh.favicon-storage', {
  providedIn: 'root',
  factory: () => {
    try {
      const s = globalThis.localStorage;
      s.getItem(FAVICON_KEY);
      return s;
    } catch {
      return null;
    }
  },
});

@Injectable({ providedIn: 'root' })
export class FaviconPref {
  private readonly storage = inject(FAVICON_STORAGE);
  readonly enabled = signal(this.read());

  set(on: boolean): void {
    this.enabled.set(on);
    try {
      if (on) this.storage?.setItem(FAVICON_KEY, '1');
      else this.storage?.removeItem(FAVICON_KEY);
    } catch {
      // this page only
    }
  }

  private read(): boolean {
    try {
      return this.storage?.getItem(FAVICON_KEY) === '1';
    } catch {
      return false;
    }
  }
}
