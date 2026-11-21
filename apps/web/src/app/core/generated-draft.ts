import { computed, signal } from '@angular/core';

/**
 * A generated value awaiting an explicit Save or "Use this password",
 * together with a copy of the settings that produced it.
 *
 * When the current settings differ from that copy the value is `outdated`
 * and no longer offered (`current` is null) until the user generates again,
 * so an old value never stands in for new settings. Plain signals only; the
 * owning component clears it on lock, navigation and destroy.
 */
export class GeneratedDraft<P> {
  private readonly state = signal<{ value: string; params: P } | null>(null);

  constructor(
    private readonly params: () => P,
    private readonly same: (a: P, b: P) => boolean,
  ) {}

  readonly current = computed(() => {
    const s = this.state();
    return s && this.same(s.params, this.params()) ? s.value : null;
  });

  readonly outdated = computed(() => {
    const s = this.state();
    return !!s && !this.same(s.params, this.params());
  });

  /** `params` must be the exact settings the value was generated with. */
  set(value: string, params: P): void {
    this.state.set({ value, params: structuredClone(params) });
  }

  clear(): void {
    this.state.set(null);
  }
}
