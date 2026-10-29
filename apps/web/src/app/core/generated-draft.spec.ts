/**
 * A generated value is only offered while the settings that produced it are
 * still the current ones; an old value never stands in for new settings.
 */
import { signal } from '@angular/core';
import { GeneratedDraft } from './generated-draft';

describe('GeneratedDraft', () => {
  const same = (a: { n: number }, b: { n: number }) => a.n === b.n;

  it('offers the value generated with the current settings', () => {
    const p = signal({ n: 1 });
    const d = new GeneratedDraft(p, same);
    expect(d.current()).toBeNull();
    expect(d.outdated()).toBe(false);
    d.set('v1', p());
    expect(d.current()).toBe('v1');
    expect(d.outdated()).toBe(false);
  });

  it('a settings change makes it outdated until regenerated', () => {
    const p = signal({ n: 1 });
    const d = new GeneratedDraft(p, same);
    d.set('v1', p());
    p.set({ n: 2 });
    expect(d.current()).toBeNull();
    expect(d.outdated()).toBe(true);
    d.set('v2', p());
    expect(d.current()).toBe('v2');
    expect(d.outdated()).toBe(false);
  });

  it('captures the settings by value', () => {
    const o = { n: 1 };
    const p = signal(o);
    const d = new GeneratedDraft(p, same);
    d.set('v1', o);
    o.n = 5; // mutated in place (not how settings change, but must not matter)
    p.set({ n: 5 });
    expect(d.current()).toBeNull();
  });

  it('clear drops the value and the outdated state', () => {
    const p = signal({ n: 1 });
    const d = new GeneratedDraft(p, same);
    d.set('v1', p());
    p.set({ n: 2 });
    d.clear();
    expect(d.current()).toBeNull();
    expect(d.outdated()).toBe(false);
  });
});
