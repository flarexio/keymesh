import { Component, inject } from '@angular/core';
import { I18n } from '../core/i18n/i18n.service';
import { Icon } from '../shared/icon';

/** The 1Password importer is native-only; the browser never runs `op`. */
@Component({
  selector: 'km-import-info',
  imports: [Icon],
  template: `
    <div class="page">
      <header class="page-head">
        <h2 id="import-title">{{ i18n.t('import.title') }}</h2>
        <p class="lead">{{ i18n.t('import.lead') }}</p>
      </header>
      <section class="card tool-card" aria-labelledby="import-cli">
        <h3 id="import-cli" class="card-title"><km-icon name="terminal" />{{ i18n.t('import.cliTitle') }}</h3>
        <pre class="code-block" tabindex="0" [attr.aria-label]="i18n.t('import.commands')"><code>keymesh import-op preview --op-vault "&lt;vault&gt;" --item "&lt;item&gt;"
keymesh import-op apply   --op-vault "&lt;vault&gt;" --item "&lt;item&gt;"
keymesh import-op preview --account "&lt;account&gt;" --ref "op://&lt;vault&gt;/&lt;item&gt;/&lt;field&gt;"</code></pre>
        <ul class="check-list">
          <li class="no"><km-icon name="x" /><span>{{ i18n.t('import.noBrowser') }}</span></li>
          <li class="no"><km-icon name="x" /><span>{{ i18n.t('import.noCredentials') }}</span></li>
          <li><km-icon name="info" /><span>{{ i18n.t('import.separate') }}</span></li>
        </ul>
      </section>
    </div>
  `,
})
export class ImportInfo {
  protected readonly i18n = inject(I18n);
}
