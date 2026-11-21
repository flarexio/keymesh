/**
 * In-app confirmation dialog (native modal <dialog>: focus trap, Escape,
 * inert background) and a polite toast region. Both store message keys, not
 * rendered text, so they follow a language switch while open.
 */
import {
  Component,
  ElementRef,
  Injectable,
  Injector,
  afterNextRender,
  effect,
  inject,
  signal,
  viewChild,
} from '@angular/core';
import { I18n, Message, MessageKey, Params } from '../core/i18n/i18n.service';
import { Icon, IconName } from './icon';

export interface ConfirmOptions {
  title: MessageKey;
  body: MessageKey;
  params?: Params;
  confirm: MessageKey;
  danger?: boolean;
}

interface PendingConfirm extends ConfirmOptions {
  resolve: (ok: boolean) => void;
}

@Injectable({ providedIn: 'root' })
export class ConfirmService {
  readonly current = signal<PendingConfirm | null>(null);

  ask(options: ConfirmOptions): Promise<boolean> {
    this.settle(false);
    return new Promise((resolve) => this.current.set({ ...options, resolve }));
  }

  /** Resolve the open request (if any); `false` = cancelled. */
  settle(ok: boolean): void {
    const c = this.current();
    if (!c) return;
    this.current.set(null);
    c.resolve(ok);
  }
}

@Component({
  selector: 'km-confirm-dialog',
  imports: [Icon],
  template: `
    <dialog #dlg class="dialog" aria-labelledby="confirm-title" aria-describedby="confirm-body"
      (cancel)="$event.preventDefault(); confirm.settle(false)">
      @if (confirm.current(); as c) {
        <div class="dialog-body">
          <span class="dialog-icon" [class.danger]="c.danger"><km-icon [name]="c.danger ? 'alert' : 'info'" /></span>
          <div>
            <h2 id="confirm-title">{{ i18n.t(c.title, c.params) }}</h2>
            <p id="confirm-body">{{ i18n.t(c.body, c.params) }}</p>
          </div>
        </div>
        <div class="dialog-actions">
          <button type="button" class="btn" autofocus (click)="confirm.settle(false)">{{ i18n.t('common.cancel') }}</button>
          <button type="button" class="btn" [class.btn-danger]="c.danger" [class.btn-primary]="!c.danger"
            data-testid="confirm-accept" (click)="confirm.settle(true)">{{ i18n.t(c.confirm, c.params) }}</button>
        </div>
      }
    </dialog>
  `,
})
export class ConfirmDialog {
  protected readonly confirm = inject(ConfirmService);
  protected readonly i18n = inject(I18n);
  private readonly dlg = viewChild.required<ElementRef<HTMLDialogElement>>('dlg');
  private readonly injector = inject(Injector);

  constructor() {
    effect(() => {
      const el = this.dlg().nativeElement;
      if (this.confirm.current()) {
        if (!el.open) el.showModal();
        // The buttons render after this effect: focus the safe choice then.
        afterNextRender(() => el.querySelector<HTMLElement>('[autofocus]')?.focus(), {
          injector: this.injector,
        });
      } else if (el.open) {
        el.close();
      }
    });
  }
}

export type ToastTone = 'success' | 'info' | 'error';

interface Toast extends Message {
  id: number;
  tone: ToastTone;
}

@Injectable({ providedIn: 'root' })
export class ToastService {
  readonly toasts = signal<Toast[]>([]);
  private next = 0;

  show(key: MessageKey, tone: ToastTone = 'success', params?: Params): void {
    const id = ++this.next;
    this.toasts.update((t) => [...t.slice(-2), { id, key, params, tone }]);
    setTimeout(() => this.dismiss(id), 4000);
  }

  dismiss(id: number): void {
    this.toasts.update((t) => t.filter((x) => x.id !== id));
  }

  clear(): void {
    this.toasts.set([]);
  }
}

const TOAST_ICONS: Record<ToastTone, IconName> = { success: 'check', info: 'info', error: 'alert' };

@Component({
  selector: 'km-toasts',
  imports: [Icon],
  template: `
    <div class="toasts" role="status" aria-live="polite" data-testid="toasts">
      @for (t of toast.toasts(); track t.id) {
        <div class="toast" [attr.data-tone]="t.tone">
          <km-icon [name]="icon(t.tone)" />
          <span>{{ i18n.msg(t) }}</span>
          <button type="button" class="icon-btn" [attr.aria-label]="i18n.t('common.dismiss')" (click)="toast.dismiss(t.id)">
            <km-icon name="x" />
          </button>
        </div>
      }
    </div>
  `,
})
export class Toasts {
  protected readonly toast = inject(ToastService);
  protected readonly i18n = inject(I18n);
  protected icon(tone: ToastTone): IconName {
    return TOAST_ICONS[tone];
  }
}
