import { TOTP_WARN_SECONDS, countdownState } from './totp-countdown';

describe('TOTP countdown', () => {
  it('warns in the last five seconds only, across a 30 s rollover', () => {
    expect(TOTP_WARN_SECONDS).toBe(5);
    expect(countdownState(30, 30)).toEqual({ fraction: 1, warn: false });
    expect(countdownState(6, 30)).toEqual({ fraction: 0.2, warn: false });
    expect(countdownState(5, 30).warn).toBe(true);
    expect(countdownState(1, 30).warn).toBe(true);
    // Next period starts full again.
    expect(countdownState(30, 30).warn).toBe(false);
  });

  it('clamps bad input and supports other periods', () => {
    expect(countdownState(-3, 30)).toEqual({ fraction: 0, warn: true });
    expect(countdownState(99, 30)).toEqual({ fraction: 1, warn: false });
    expect(countdownState(60, 60).fraction).toBe(1);
    expect(countdownState(10, 0)).toEqual({ fraction: 1 / 3, warn: false });
  });
});
