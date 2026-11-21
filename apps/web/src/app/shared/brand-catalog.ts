import { Injectable, signal } from '@angular/core';
import type { Brand } from '../core/brand-icons';

/**
 * Brand icon catalogue (about 90 kB of path data), loaded as its own lazy
 * chunk right after start-up so it never delays the first render. The
 * service worker prefetches every chunk, so it is also available offline.
 */
@Injectable({ providedIn: 'root' })
export class BrandCatalog {
  readonly brands = signal<readonly Brand[]>([]);

  constructor() {
    import('../core/brand-icons').then(
      (m) => this.brands.set(m.BRANDS),
      () => {
        // Unavailable: logins keep their category or letter icon.
      },
    );
  }
}
