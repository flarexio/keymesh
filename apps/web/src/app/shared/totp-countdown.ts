import { Component, computed, input } from '@angular/core';

/** Seconds before expiry when the code is flagged (authenticator-app convention). */
export const TOTP_WARN_SECONDS = 5;

export interface CountdownState {
  /** 0..1 of the period still left. */
  fraction: number;
  warn: boolean;
}

/** Pure, clamped: tested directly (no timers). */
export function countdownState(remaining: number, period: number): CountdownState {
  const p = period > 0 ? period : 30;
  const r = Math.min(Math.max(remaining, 0), p);
  return { fraction: r / p, warn: r <= TOTP_WARN_SECONDS };
}

const R = 15.9155; // circumference 100: dash values are percentages

/**
 * Circular countdown beside a TOTP code. Decorative for assistive tech:
 * the caller shows the seconds as text (the accessible value). The warning
 * is never colour-only: the caller also changes its text.
 */
@Component({
  selector: 'km-totp-countdown',
  template: `
    <svg viewBox="0 0 36 36" class="totp-ring" [class.warn]="state().warn" aria-hidden="true" data-testid="totp-ring"
      [attr.data-warn]="state().warn">
      <circle class="track" cx="18" cy="18" [attr.r]="r" />
      <circle class="arc" cx="18" cy="18" [attr.r]="r" pathLength="100"
        [attr.stroke-dasharray]="state().fraction * 100 + ' 100'" />
      <text x="18" y="18" class="num">{{ remaining() }}</text>
    </svg>
  `,
})
export class TotpCountdown {
  readonly remaining = input.required<number>();
  readonly period = input(30);
  protected readonly r = R;
  readonly state = computed(() => countdownState(this.remaining(), this.period()));
}
