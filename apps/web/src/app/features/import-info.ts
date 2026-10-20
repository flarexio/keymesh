import { Component } from '@angular/core';

/** The 1Password importer is native-only; the browser never runs `op`. */
@Component({
  selector: 'km-import-info',
  template: `
    <section class="panel" aria-labelledby="import-title">
      <h2 id="import-title">Import from 1Password (CLI only)</h2>
      <p>
        Importing runs only in the native <code>keymesh</code> CLI, using your already signed-in
        <code>op</code> CLI on your own machine. This browser app cannot run <code>op</code>, has no
        server endpoint for it, and never asks for 1Password credentials.
      </p>
      <pre class="mono">keymesh import-op preview --op-vault "&lt;vault&gt;" --item "&lt;item&gt;"
keymesh import-op apply   --op-vault "&lt;vault&gt;" --item "&lt;item&gt;"
keymesh import-op preview --account "&lt;account&gt;" --ref "op://&lt;vault&gt;/&lt;item&gt;/&lt;field&gt;"</pre>
      <p class="hint">
        The CLI vault file and this browser demo vault are separate. Moving data between them is not
        implemented yet. During development, run the importer only against the fake <code>op</code>
        fixture.
      </p>
    </section>
  `,
})
export class ImportInfo {}
