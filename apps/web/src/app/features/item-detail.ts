import {
  Component,
  OnDestroy,
  OnInit,
  computed,
  inject,
  input,
  output,
  signal,
} from '@angular/core';
import { DatePipe } from '@angular/common';
import { VaultService } from '../core/vault.service';
import { ItemView, KIND_LABELS, Labeled } from '../core/types';
import { SecretField } from './secret-field';

@Component({
  selector: 'km-item-detail',
  imports: [SecretField, DatePipe],
  template: `
    @if (view(); as v) {
      <article class="detail" aria-labelledby="detail-title">
        <header class="detail-head">
          <div>
            <p class="kind-chip">{{ kindLabel(v) }}</p>
            <h2 id="detail-title">{{ v.title }}</h2>
            @if (v.tags.length) {
              <p class="tags">
                @for (t of v.tags; track t) {
                  <span class="tag">{{ t }}</span>
                }
              </p>
            }
          </div>
          <div class="actions">
            <button type="button" (click)="edit.emit(v.id)">Edit</button>
            <button type="button" class="danger" (click)="remove(v)">Delete</button>
          </div>
        </header>

        @if (totp(); as t) {
          <section class="totp" aria-label="Current one-time code">
            <span class="totp-code mono" data-testid="totp-code">{{ t.code }}</span>
            <span class="totp-remaining" data-testid="totp-remaining"
              >{{ t.remaining }}s remaining</span
            >
            <progress [value]="t.remaining" [max]="period()" aria-hidden="true"></progress>
          </section>
        }

        <dl class="fields">
          @for (f of plainFields(); track f.label) {
            <dt>{{ f.label }}</dt>
            <dd [class.mono]="f.mono">{{ f.value }}</dd>
          }
        </dl>

        @for (l of lists(); track l.label) {
          <section>
            <h3>{{ l.label }}</h3>
            <ul class="plain-list">
              @for (x of l.values; track $index) {
                <li>
                  @if (x.label) {
                    <span class="muted">{{ x.label }}:</span>
                  }
                  {{ x.value }}
                </li>
              }
            </ul>
          </section>
        }

        @if (v.secrets.length) {
          <section aria-label="Protected fields">
            <h3>Protected fields</h3>
            @for (s of v.secrets; track s.key) {
              <km-secret-field [itemId]="v.id" [slot]="s.key" [label]="s.label" />
            }
          </section>
        }

        @if (visibleCustom().length) {
          <section>
            <h3>Custom fields</h3>
            <dl class="fields">
              @for (c of visibleCustom(); track c.index) {
                <dt>{{ c.section ? c.section + ' / ' : '' }}{{ c.label }}</dt>
                <dd>{{ c.value }}</dd>
              }
            </dl>
          </section>
        }

        <p class="meta muted">
          Revision {{ v.rev }} · updated {{ v.updated_at * 1000 | date: 'medium' }}
          @if (v.imported) {
            · imported
          }
        </p>
      </article>
    } @else if (loaded().error) {
      <p role="alert" class="error">{{ loaded().error }}</p>
    }
    @if (error()) {
      <p role="alert" class="error">{{ error() }}</p>
    }
  `,
})
export class ItemDetail implements OnInit, OnDestroy {
  private readonly vault = inject(VaultService);
  readonly itemId = input.required<string>();
  readonly edit = output<string>();
  readonly deleted = output<void>();
  protected readonly error = signal<string | null>(null);
  private readonly tick = signal(0);
  private timer: ReturnType<typeof setInterval> | null = null;

  private readonly loaded = computed<{ view: ItemView | null; error: string | null }>(() => {
    this.vault.version();
    try {
      return { view: this.vault.get(this.itemId()), error: null };
    } catch (e) {
      return { view: null, error: e instanceof Error ? e.message : 'Cannot load item' };
    }
  });
  protected readonly view = computed(() => this.loaded().view);

  /** TOTP item itself, or the TOTP linked from a login. */
  private readonly totpId = computed(() => {
    const v = this.view();
    if (!v) return null;
    if (v.kind === 'totp') return v.id;
    if (v.kind === 'login') return (v.data['totp_item'] as string | null) ?? null;
    return null;
  });

  protected readonly period = computed(() => {
    const v = this.view();
    return v?.kind === 'totp' ? (v.data['period'] as number) : 30;
  });

  protected readonly totp = computed(() => {
    this.tick();
    const id = this.totpId();
    if (!id) return null;
    try {
      return this.vault.totp(id);
    } catch {
      return null;
    }
  });

  protected readonly plainFields = computed(() => {
    const v = this.view();
    if (!v) return [];
    const d = v.data;
    const out: { label: string; value: string; mono?: boolean }[] = [];
    const add = (label: string, val: unknown, mono = false) => {
      if (val !== null && val !== undefined && val !== '') out.push({ label, value: String(val), mono });
    };
    switch (v.kind) {
      case 'login':
        add('Username', d['username']);
        add('Recovery codes', d['recovery_code_count'] ? `${d['recovery_code_count']} stored` : null);
        add('Linked TOTP', d['totp_item'] ? 'yes (code shown above)' : null);
        break;
      case 'secret':
        add('Service', d['service']);
        add('Username', d['username']);
        add('Format', d['format']);
        add('Origin', d['origin'] === 'generated' ? 'generated locally (not provider-issued)' : d['origin']);
        break;
      case 'contact':
        add('Name', d['full_name']);
        add('Organization', d['organization']);
        break;
      case 'crypto_wallet':
        add('Wallet software', d['wallet_software']);
        add('Network', d['network']);
        add('Derivation path', d['derivation_path'], true);
        break;
      case 'totp':
        add('Issuer', d['issuer']);
        add('Account', d['account_name']);
        add('Algorithm', d['algorithm']);
        add('Digits', d['digits']);
        add('Period', `${d['period']}s`);
        break;
      case 'ed25519_key':
        add('Comment', d['comment']);
        add('Public key (hex)', d['public_key_hex'], true);
        add('OpenSSH public key', d['openssh'], true);
        add('Private key', 'stored encrypted; no export or signing in this demo');
        break;
      case 'secure_note':
        break;
    }
    return out;
  });

  protected readonly lists = computed(() => {
    const v = this.view();
    if (!v) return [];
    const d = v.data;
    const out: { label: string; values: Labeled[] }[] = [];
    const add = (label: string, val: unknown) => {
      const arr = (val as Labeled[] | undefined) ?? [];
      if (arr.length) out.push({ label, values: arr });
    };
    if (v.kind === 'login') {
      add('URLs', ((d['urls'] as string[]) ?? []).map((u) => ({ label: null, value: u })));
    }
    if (v.kind === 'contact') {
      add('Emails', d['emails']);
      add('Phones', d['phones']);
      add('Addresses', d['addresses']);
      add('Websites', d['websites']);
    }
    if (v.kind === 'crypto_wallet') add('Addresses', d['addresses']);
    return out;
  });

  protected readonly visibleCustom = computed(
    () => this.view()?.custom_fields.filter((c) => !c.concealed) ?? [],
  );

  protected kindLabel(v: ItemView): string {
    return KIND_LABELS[v.kind];
  }

  protected async remove(v: ItemView): Promise<void> {
    if (!confirm(`Delete "${v.title}" from the demo vault?`)) return;
    try {
      await this.vault.deleteItem(v.id);
      this.deleted.emit();
    } catch (e) {
      this.error.set(e instanceof Error ? e.message : 'Delete failed');
    }
  }

  ngOnInit(): void {
    this.timer = setInterval(() => this.tick.update((t) => t + 1), 1000);
  }

  ngOnDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}
