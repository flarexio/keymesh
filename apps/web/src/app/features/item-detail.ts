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
import { errorKey } from '../core/errors';
import { I18n, Message, MessageKey } from '../core/i18n/i18n.service';
import { VaultService } from '../core/vault.service';
import { ItemView, Labeled, SecretSlot } from '../core/types';
import { ConfirmService, ToastService } from '../shared/feedback';
import { Icon, KIND_ICONS } from '../shared/icon';
import { SecretField } from './secret-field';

/** Core slot keys → localized labels; custom fields keep the user's label. */
const SLOT_LABELS: Record<string, MessageKey> = {
  notes: 'field.notes',
  password: 'field.password',
  secret: 'field.secret',
  recovery_phrase: 'field.recoveryPhrase',
  wallet_password: 'field.walletPassword',
  private_key: 'field.privateKey',
  totp_secret: 'field.totpSecret',
  body: 'field.note',
};

interface PlainField {
  label: MessageKey;
  value?: string;
  /** Localized value (instead of user/technical data). */
  message?: Message;
  mono?: boolean;
}

@Component({
  selector: 'km-item-detail',
  imports: [SecretField, Icon],
  template: `
    @if (view(); as v) {
      <article class="detail" aria-labelledby="detail-title">
        <header class="detail-head">
          <span class="kind-tile kind-tile-lg" [attr.data-kind]="v.kind"><km-icon [name]="icon(v)" /></span>
          <div class="detail-heading">
            <p class="eyebrow">{{ i18n.t(kindKey(v)) }}</p>
            <h2 id="detail-title">{{ v.title }}</h2>
            @if (v.tags.length) {
              <ul class="tags" [attr.aria-label]="i18n.t('field.tags')">
                @for (t of v.tags; track t) {
                  <li class="tag">{{ t }}</li>
                }
              </ul>
            }
          </div>
          <div class="detail-actions">
            <button type="button" data-testid="edit" class="btn" (click)="edit.emit(v.id)"><km-icon name="edit" /><span>{{ i18n.t('common.edit') }}</span></button>
            <button type="button" data-testid="delete" class="btn btn-danger-ghost" (click)="remove(v)"><km-icon name="trash" /><span>{{ i18n.t('common.delete') }}</span></button>
          </div>
        </header>

        @if (totp(); as t) {
          <section class="totp-card" [attr.aria-label]="i18n.t('detail.totpRegion')">
            <div>
              <p class="section-label">{{ i18n.t('detail.oneTimeCode') }}</p>
              <span class="totp-code mono" data-testid="totp-code">{{ t.code }}</span>
            </div>
            <div class="totp-timer">
              <span class="totp-remaining" data-testid="totp-remaining">{{ i18n.t('detail.secondsRemaining', { s: t.remaining }) }}</span>
              <progress [value]="t.remaining" [max]="period()" aria-hidden="true"></progress>
            </div>
          </section>
        }

        @if (plainFields().length) {
          <section class="detail-section">
            <h3 class="section-label">{{ i18n.t('detail.details') }}</h3>
            <dl class="fields">
              @for (f of plainFields(); track f.label) {
                <div class="field-row">
                  <dt>{{ i18n.t(f.label) }}</dt>
                  <dd [class.mono]="f.mono">{{ f.message ? i18n.msg(f.message) : f.value }}</dd>
                </div>
              }
            </dl>
          </section>
        }

        @for (l of lists(); track l.label) {
          <section class="detail-section">
            <h3 class="section-label">{{ i18n.t(l.label) }}</h3>
            <ul class="value-list">
              @for (x of l.values; track $index) {
                <li>
                  @if (x.label) {
                    <span class="value-label">{{ x.label }}</span>
                  }
                  <span class="value-text" [class.mono]="l.mono">{{ x.value }}</span>
                </li>
              }
            </ul>
          </section>
        }

        @if (v.secrets.length) {
          <section class="detail-section" [attr.aria-label]="i18n.t('detail.protected')">
            <h3 class="section-label"><km-icon name="shield" />{{ i18n.t('detail.protected') }}</h3>
            <div class="secret-list">
              @for (s of v.secrets; track s.key) {
                <km-secret-field [itemId]="v.id" [slot]="s.key" [label]="slotLabel(s)" />
              }
            </div>
          </section>
        }

        @if (visibleCustom().length) {
          <section class="detail-section">
            <h3 class="section-label">{{ i18n.t('field.customFields') }}</h3>
            <dl class="fields">
              @for (c of visibleCustom(); track c.index) {
                <div class="field-row">
                  <dt>{{ c.section ? c.section + ' / ' : '' }}{{ c.label }}</dt>
                  <dd>{{ c.value }}</dd>
                </div>
              }
            </dl>
          </section>
        }

        <p class="item-meta" data-testid="item-meta" [attr.data-rev]="v.rev">
          {{ i18n.t('detail.meta', { date: i18n.dateTime(v.updated_at * 1000) }) }}
          @if (v.imported) {
            · {{ i18n.t('detail.imported') }}
          }
        </p>
      </article>
    } @else if (loaded().error; as e) {
      <div class="callout callout-danger" role="alert"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
    }
    @if (error(); as e) {
      <div class="callout callout-danger" role="alert"><km-icon name="alert" /><p>{{ i18n.t(e) }}</p></div>
    }
  `,
})
export class ItemDetail implements OnInit, OnDestroy {
  private readonly vault = inject(VaultService);
  protected readonly i18n = inject(I18n);
  private readonly confirm = inject(ConfirmService);
  private readonly toast = inject(ToastService);
  readonly itemId = input.required<string>();
  readonly edit = output<string>();
  readonly deleted = output<void>();
  protected readonly error = signal<MessageKey | null>(null);
  private readonly tick = signal(0);
  private timer: ReturnType<typeof setInterval> | null = null;

  protected readonly loaded = computed<{ view: ItemView | null; error: MessageKey | null }>(() => {
    this.vault.version();
    try {
      return { view: this.vault.get(this.itemId()), error: null };
    } catch (e) {
      return { view: null, error: errorKey(e) };
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
    const out: PlainField[] = [];
    const add = (label: MessageKey, val: unknown, mono = false) => {
      if (val !== null && val !== undefined && val !== '') out.push({ label, value: String(val), mono });
    };
    const say = (label: MessageKey, message: Message) => out.push({ label, message });
    switch (v.kind) {
      case 'login':
        add('field.username', d['username']);
        if (d['recovery_code_count']) {
          say('field.recoveryCodes', { key: 'detail.recoveryStored', params: { n: d['recovery_code_count'] as number } });
        }
        if (d['totp_item']) say('field.linkedTotp', { key: 'detail.linkedTotpYes' });
        break;
      case 'secret':
        add('field.service', d['service']);
        add('field.username', d['username']);
        add('field.format', d['format'], true);
        if (d['origin'] === 'generated') say('field.origin', { key: 'detail.originGenerated' });
        else if (d['origin'] === 'imported') say('field.origin', { key: 'detail.originImported' });
        else if (d['origin'] === 'manual') say('field.origin', { key: 'detail.originManual' });
        break;
      case 'contact':
        add('field.fullName', d['full_name']);
        add('field.organization', d['organization']);
        break;
      case 'crypto_wallet':
        add('field.walletSoftware', d['wallet_software']);
        add('field.network', d['network']);
        add('field.derivationPath', d['derivation_path'], true);
        break;
      case 'totp':
        add('field.issuer', d['issuer']);
        add('field.account', d['account_name']);
        add('field.algorithm', d['algorithm'], true);
        add('field.digits', d['digits']);
        say('field.period', { key: 'detail.periodSeconds', params: { s: d['period'] as number } });
        break;
      case 'ed25519_key':
        add('field.comment', d['comment']);
        add('field.publicKeyHex', d['public_key_hex'], true);
        add('field.openssh', d['openssh'], true);
        say('field.privateKey', { key: 'detail.privateKeyStored' });
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
    const out: { label: MessageKey; values: Labeled[]; mono?: boolean }[] = [];
    const add = (label: MessageKey, val: unknown, mono = false) => {
      const arr = (val as Labeled[] | undefined) ?? [];
      if (arr.length) out.push({ label, values: arr, mono });
    };
    if (v.kind === 'login') {
      add('field.urls', ((d['urls'] as string[]) ?? []).map((u) => ({ label: null, value: u })));
    }
    if (v.kind === 'contact') {
      add('field.emails', d['emails']);
      add('field.phones', d['phones']);
      add('field.addresses', d['addresses']);
      add('field.websites', d['websites']);
    }
    if (v.kind === 'crypto_wallet') add('field.walletAddresses', d['addresses'], true);
    return out;
  });

  protected readonly visibleCustom = computed(
    () => this.view()?.custom_fields.filter((c) => !c.concealed) ?? [],
  );

  protected kindKey(v: ItemView): MessageKey {
    return `kind.${v.kind}`;
  }

  protected icon(v: ItemView) {
    return KIND_ICONS[v.kind];
  }

  /** Localized label for a core slot, or the user's own custom-field label. */
  protected slotLabel(s: SecretSlot): string {
    const fixed = SLOT_LABELS[s.key];
    if (fixed) return this.i18n.t(fixed);
    const rc = /^recovery_code:(\d+)$/.exec(s.key);
    if (rc) return this.i18n.t('field.recoveryCodeN', { n: Number(rc[1]) + 1 });
    return s.label;
  }

  protected async remove(v: ItemView): Promise<void> {
    const ok = await this.confirm.ask({
      title: 'detail.deleteTitle',
      body: 'detail.deleteBody',
      params: { title: v.title },
      confirm: 'common.delete',
      danger: true,
    });
    if (!ok) return;
    try {
      await this.vault.deleteItem(v.id);
      this.toast.show('detail.deleted');
      this.deleted.emit();
    } catch (e) {
      this.error.set(errorKey(e));
    }
  }

  ngOnInit(): void {
    this.timer = setInterval(() => this.tick.update((t) => t + 1), 1000);
  }

  ngOnDestroy(): void {
    if (this.timer) clearInterval(this.timer);
  }
}
