/**
 * Start screen layout with a stub VaultService (no WASM, no storage): with a
 * password vault stored and locked, only unlock is shown; delete, the demo,
 * restore, the overview and the limits sit in a collapsed "More options".
 * Real unlock, delete and demo behaviour is covered by the browser E2E.
 */
import { signal } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { VaultService } from '../core/vault.service';
import { ConfirmService } from '../shared/feedback';
import { en } from '../core/i18n/en';
import { Start } from './start';

interface Opts {
  secure?: boolean;
  protectedStored?: boolean;
  passkey?: boolean;
  confirming?: boolean;
  demo?: 'empty' | 'locked' | 'stored';
  passkeyFails?: boolean;
}

function stubVault(o: Opts) {
  return {
    secure: o.secure ?? true,
    status: signal(o.demo ?? 'empty'),
    protectedStored: signal(o.protectedStored ? { vault_id: 'synthetic' } : null),
    confirmingNewVault: signal(o.confirming ?? false),
    protectedReloaded: signal(false),
    credentialBusy: signal(false),
    storedQuickUnlock: signal(o.passkey ? [{ rp_id: location.hostname }] : []),
    quickUnlockSupported: () => !!o.passkey,
    storedNeedsLostKey: () => false,
    canOpenStored: () => true,
    newVaultRecoveryCode: () => '',
    newVaultId: () => null,
    checkNewPassword: () => undefined,
    discardProtected: vi.fn(async () => undefined),
    discard: vi.fn(async () => undefined),
    startNew: vi.fn(async () => undefined),
    restore: vi.fn(async () => undefined),
    openStored: vi.fn(async () => undefined),
    unlockWithPassword: vi.fn(async () => undefined),
    unlockWithQuickUnlock: vi.fn(async (): Promise<void> => {
      if (o.passkeyFails) throw new Error('The passkey request was cancelled.');
    }),
  };
}

type Stub = ReturnType<typeof stubVault>;

async function render(o: Opts): Promise<{ f: ComponentFixture<Start>; vault: Stub; el: HTMLElement }> {
  const vault = stubVault(o);
  TestBed.configureTestingModule({ providers: [{ provide: VaultService, useValue: vault }, ConfirmService] });
  const f = TestBed.createComponent(Start);
  document.body.appendChild(f.nativeElement);
  await f.whenStable();
  return { f, vault, el: f.nativeElement as HTMLElement };
}

const q = (el: HTMLElement, id: string) => el.querySelector<HTMLElement>(`[data-testid="${id}"]`);
/** Rendered and not inside a closed <details> or an inert (collapsed) panel. */
function shown(el: HTMLElement, id: string): boolean {
  const n = q(el, id);
  if (!n) return false;
  if (n.closest('[inert]')) return false;
  for (let p = n.parentElement; p; p = p.parentElement) {
    if (p instanceof HTMLDetailsElement && !p.open && !(n.closest('summary') && n.closest('details') === p)) return false;
  }
  return true;
}

afterEach(() => {
  document.body.querySelectorAll('km-start, [ng-version]').forEach((n) => n.remove());
  TestBed.resetTestingModule();
});

describe('Start: locked password vault', () => {
  it('shows only unlock, the forgot link and the experimental hint; the rest is collapsed under More options', async () => {
    const { el } = await render({ protectedStored: true, demo: 'locked' });
    for (const id of ['unlock-password', 'unlock-protected', 'forgot-password', 'protected-experimental', 'more-options']) {
      expect(shown(el, id), id).toBe(true);
    }
    const more = q(el, 'more-options') as HTMLDetailsElement;
    expect(more.tagName).toBe('DETAILS');
    expect(more.open).toBe(false);
    expect(more.querySelector('summary')?.textContent).toContain(en['start.more.title']);
    for (const id of ['delete-protected', 'demo-section', 'unlock', 'vault-overview', 'start-limits']) {
      expect(q(el, id), `${id} still exists`).not.toBeNull();
      expect(shown(el, id), `${id} hidden`).toBe(false);
    }
    // The delete action is not duplicated in the unlock card.
    expect(el.querySelectorAll('[data-testid="delete-protected"]').length).toBe(1);
    expect(q(el, 'protected-section')?.contains(q(el, 'delete-protected'))).toBe(false);
  });

  it('expanded: delete still asks for confirmation, and the demo and restore are there', async () => {
    const { f, vault, el } = await render({ protectedStored: true });
    const more = q(el, 'more-options') as HTMLDetailsElement;
    more.open = true;
    await f.whenStable();
    for (const id of ['delete-protected', 'demo-section', 'start-vault', 'initial-restore-input', 'vault-overview', 'start-limits']) {
      expect(shown(el, id), id).toBe(true);
    }
    const confirm = TestBed.inject(ConfirmService);
    q(el, 'delete-protected')!.click();
    expect(confirm.current()?.title).toBe('protected.delete.title');
    expect(vault.discardProtected).not.toHaveBeenCalled();
    confirm.settle(false);
    await f.whenStable();
    expect(vault.discardProtected).not.toHaveBeenCalled();
    q(el, 'delete-protected')!.click();
    confirm.settle(true);
    await f.whenStable();
    expect(vault.discardProtected).toHaveBeenCalledTimes(1);
  });

  it('passkey here: the passkey button is the primary action and gets focus (nothing is triggered)', async () => {
    const { vault, el } = await render({ protectedStored: true, passkey: true });
    await new Promise((r) => setTimeout(r, 0));
    expect(shown(el, 'unlock-passkey')).toBe(true);
    expect(q(el, 'unlock-passkey')?.classList.contains('btn-primary')).toBe(true);
    expect(document.activeElement).toBe(q(el, 'unlock-passkey'));
    expect(vault.unlockWithQuickUnlock).not.toHaveBeenCalled();
  });

  it('no passkey: the password field gets focus', async () => {
    const { el } = await render({ protectedStored: true });
    await new Promise((r) => setTimeout(r, 0));
    expect(q(el, 'unlock-passkey')).toBeNull();
    expect(document.activeElement).toBe(q(el, 'unlock-password'));
  });

  it('the reset view replaces the unlock form and keeps the compact layout', async () => {
    const { f, el } = await render({ protectedStored: true });
    q(el, 'forgot-password')!.click();
    await f.whenStable();
    expect(shown(el, 'reset-code')).toBe(true);
    expect(shown(el, 'demo-section')).toBe(false);
    expect(shown(el, 'more-options')).toBe(true);
  });
});

describe('Start: passkey-first lock screen', () => {
  const tick = () => new Promise((r) => setTimeout(r, 0));

  it('the passkey is the hero; the master password is collapsed behind "Use master password"', async () => {
    const { el } = await render({ protectedStored: true, passkey: true });
    await tick();
    const hero = q(el, 'passkey-hero')!;
    expect(hero).not.toBeNull();
    expect(hero.contains(q(el, 'unlock-passkey'))).toBe(true);
    expect(hero.textContent).toContain(en['qu.unlockHint']);
    expect(q(el, 'unlock-lead')?.textContent).toContain(en['protected.unlock.leadPasskey']);
    expect(q(el, 'unlock-passkey')?.classList.contains('btn-primary')).toBe(true);
    const toggle = q(el, 'use-password')!;
    expect(toggle.tagName).toBe('BUTTON');
    expect(toggle.textContent).toContain(en['protected.usePassword']);
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    const panel = el.querySelector(`#${toggle.getAttribute('aria-controls')}`)!;
    expect(panel).not.toBeNull();
    expect(panel.contains(q(el, 'unlock-password'))).toBe(true);
    expect(panel.contains(q(el, 'forgot-password'))).toBe(true);
    for (const id of ['unlock-password', 'unlock-protected', 'forgot-password']) expect(shown(el, id), id).toBe(false);
    expect(shown(el, 'more-options')).toBe(true);
    expect((q(el, 'more-options') as HTMLDetailsElement).open).toBe(false);
    expect(document.activeElement).toBe(q(el, 'unlock-passkey'));
  });

  it('expanding reveals the password and the forgot link and moves focus into the field; collapsing hides them again', async () => {
    const { f, el } = await render({ protectedStored: true, passkey: true });
    await tick();
    q(el, 'use-password')!.click();
    await f.whenStable();
    await tick();
    expect(q(el, 'use-password')!.getAttribute('aria-expanded')).toBe('true');
    for (const id of ['unlock-password', 'unlock-protected', 'forgot-password']) expect(shown(el, id), id).toBe(true);
    expect(document.activeElement).toBe(q(el, 'unlock-password'));
    q(el, 'use-password')!.click();
    await f.whenStable();
    expect(q(el, 'use-password')!.getAttribute('aria-expanded')).toBe('false');
    expect(shown(el, 'unlock-password')).toBe(false);
  });

  it('a failed or cancelled passkey shows the error and opens the master-password option (never stuck)', async () => {
    const { f, vault, el } = await render({ protectedStored: true, passkey: true, passkeyFails: true });
    await tick();
    q(el, 'unlock-passkey')!.click();
    await f.whenStable();
    await tick();
    expect(vault.unlockWithQuickUnlock).toHaveBeenCalledTimes(1);
    expect(shown(el, 'protected-error')).toBe(true);
    expect(q(el, 'use-password')!.getAttribute('aria-expanded')).toBe('true');
    expect(q(el, 'use-password')!.classList.contains('attention')).toBe(true);
    expect(shown(el, 'unlock-password')).toBe(true);
    expect(document.activeElement).toBe(q(el, 'unlock-password'));
  });

  it('nothing starts WebAuthn without a click', async () => {
    const { vault } = await render({ protectedStored: true, passkey: true });
    await tick();
    expect(vault.unlockWithQuickUnlock).not.toHaveBeenCalled();
  });

  it('without a passkey there is no toggle: the password form is shown as before', async () => {
    const { el } = await render({ protectedStored: true });
    await tick();
    expect(q(el, 'use-password')).toBeNull();
    expect(q(el, 'passkey-hero')).toBeNull();
    expect(q(el, 'unlock-lead')?.textContent).toContain(en['protected.unlock.lead']);
    for (const id of ['unlock-password', 'unlock-protected', 'forgot-password']) expect(shown(el, id), id).toBe(true);
  });
});

describe('Start: other screens are unchanged', () => {
  it('first run (no password vault): create, demo, overview and limits are all shown, no More options', async () => {
    const { el } = await render({});
    for (const id of ['create-password', 'demo-section', 'start-vault', 'vault-overview', 'start-limits']) {
      expect(shown(el, id), id).toBe(true);
    }
    expect(q(el, 'more-options')).toBeNull();
    expect(document.activeElement).not.toBe(q(el, 'create-password'));
  });

  it('insecure origin: the notice and the demo are shown, no More options', async () => {
    const { el } = await render({ secure: false, protectedStored: true });
    for (const id of ['insecure-notice', 'demo-section', 'vault-overview', 'start-limits']) expect(shown(el, id), id).toBe(true);
    expect(q(el, 'more-options')).toBeNull();
  });

  it('confirming a new recovery code: no More options', async () => {
    const { el } = await render({ protectedStored: false, confirming: true });
    expect(q(el, 'more-options')).toBeNull();
  });
});
