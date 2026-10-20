import { InjectionToken } from '@angular/core';

/** Injectable clock (Unix seconds). Tests override it, or fake `Date`. */
export interface Clock {
  nowSeconds(): number;
}

export const CLOCK = new InjectionToken<Clock>('keymesh.clock', {
  providedIn: 'root',
  factory: () => ({ nowSeconds: () => Date.now() / 1000 }),
});
