import { Component, inject } from '@angular/core';
import { I18n, MessageKey } from '../core/i18n/i18n.service';
import { LOCALES, Locale, PreferencesService, THEMES, ThemePreference } from '../core/preferences';
import { Icon, IconName } from './icon';

/** Language names are shown in their own language on purpose. The zh-TW
 * catalog stays Traditional Chinese (Taiwan); the option is labelled 中文. */
const LOCALE_LABELS: Record<Locale, { short: string; long: string }> = {
  'zh-TW': { short: '中文', long: '中文' },
  en: { short: 'EN', long: 'English' },
};

const THEME_META: Record<ThemePreference, { icon: IconName; key: MessageKey }> = {
  system: { icon: 'monitor', key: 'prefs.theme.system' },
  light: { icon: 'sun', key: 'prefs.theme.light' },
  dark: { icon: 'moon', key: 'prefs.theme.dark' },
};

/** Language and appearance controls, available in every app state. */
@Component({
  selector: 'km-display-prefs',
  imports: [Icon],
  template: `
    <div class="segmented" role="group" [attr.aria-label]="i18n.t('prefs.language')" data-testid="language-switch">
      <km-icon name="globe" class="segmented-lead" />
      @for (l of locales; track l) {
        <button type="button" [attr.aria-pressed]="prefs.locale() === l" [attr.lang]="l"
          [attr.title]="labels[l].long" [attr.aria-label]="labels[l].long" [attr.data-locale]="l"
          (click)="prefs.setLocale(l)">{{ labels[l].short }}</button>
      }
    </div>
    <div class="segmented" role="group" [attr.aria-label]="i18n.t('prefs.appearance')" data-testid="theme-switch">
      @for (th of themes; track th) {
        <button type="button" [attr.aria-pressed]="prefs.theme() === th" [attr.data-theme-option]="th"
          [attr.title]="i18n.t(meta[th].key)" (click)="prefs.setTheme(th)">
          <km-icon [name]="meta[th].icon" />
          <span class="segmented-text">{{ i18n.t(meta[th].key) }}</span>
        </button>
      }
    </div>
    @if (!prefs.persistent()) {
      <span class="prefs-note" role="note">{{ i18n.t('prefs.notSaved') }}</span>
    }
  `,
  host: { class: 'display-prefs' },
})
export class DisplayPrefs {
  protected readonly prefs = inject(PreferencesService);
  protected readonly i18n = inject(I18n);
  protected readonly locales = LOCALES;
  protected readonly themes = THEMES;
  protected readonly labels = LOCALE_LABELS;
  protected readonly meta = THEME_META;
}
