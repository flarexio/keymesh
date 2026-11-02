# Keymesh web UI design notes (M3)

The browser demo aims to look and feel like a calm, trustworthy security tool: warm neutral light surfaces, graphite dark surfaces, one restrained indigo accent, clear hierarchy and no marketing styling. The preview warning ("Preview version. Do not store real passwords.") stays visible in every state.

Sources: `apps/web/src/styles/` (`tokens.css`, `base.css`, `layout.css`, `components.css`) and `apps/web/src/app/shared/`.

## Tokens

All colours are semantic custom properties defined with `light-dark(light, dark)`. The theme is selected by `color-scheme`:

| `html[data-theme]` | Result |
|---|---|
| `light` / `dark` | forced scheme (set before first paint, then kept in sync by `PreferencesService`) |
| absent (no JS) | follows `prefers-color-scheme` |

| Group | Tokens | Use |
|---|---|---|
| Surfaces | `--bg`, `--surface`, `--surface-2`, `--surface-sunken`, `--surface-hover` | page, cards and panes, sidebar and subtle fills, inputs and code, hover |
| Lines | `--border`, `--border-strong` | dividers and cards; inputs and secondary buttons |
| Text | `--fg`, `--fg-muted`, `--fg-subtle` | body, secondary, labels/meta (all ≥ 4.5:1 on `--surface` and `--bg`) |
| Accent | `--accent`, `--accent-hover`, `--accent-fg`, `--accent-soft`, `--accent-soft-fg` | primary actions, selection, focus |
| Status | `--danger*`, `--success*`, `--warn*`, `--info-*` | destructive actions and errors, confirmations, demo/stale warnings, neutral callouts |
| Kinds | `--kind-<item kind>` | low-saturation hue per item type, always paired with an icon and a text label |
| Elevation | `--shadow-sm`, `--shadow-md`, `--shadow-lg` | cards, menus, dialogs and toasts |
| Focus | `--focus-ring` | 2px outline via `:focus-visible`; inputs add a 3px soft ring |
| Type | `--font-sans`, `--font-zh`, `--font-mono`, `--text-xs … --text-2xl`, `--leading` | system fonts only; zh-TW prefers PingFang TC / Noto Sans TC / Microsoft JhengHei and a looser line height |
| Space | `--space-1 … --space-10` (4px grid) | padding, gaps |
| Shape | `--radius-sm/md/lg/pill`, `--control-h(-sm/-lg)` | 7/10/14px radii; 38px controls (44px on coarse pointers) |

No remote fonts, images or icon fonts are loaded. Icons are a small local stroke set (`shared/icon.ts`, 24×24, `currentColor`), always decorative (`aria-hidden`) next to a text label or an `aria-label`. Emoji are not used as icons.

## Layout

- **Wide (> 860px):** a fixed app frame. The demo strip and the app bar (brand, language, appearance, Lock) sit above a sidebar (sections, categories with counts, vault status) and the workspace. Sidebar, item list and detail scroll independently, so the warning and Lock stay in view.
- **Narrow (≤ 860px):** a single column with normal page scrolling. The app bar wraps preferences onto a second row. Sections move to a bottom navigation bar, and categories become a select. The list and the detail/editor replace each other, with a "Back to list" button; focus moves to the detail when it opens. E2E checks for no horizontal overflow at 320, 360 and 390px.

## Components and conventions

- **Buttons:** primary (filled accent, one per area), secondary (outlined), ghost, and destructive (outlined in red; a filled red confirm only inside the confirmation dialog). Icon and text together; icon-only buttons carry an `aria-label` and a `title`.
- **Segmented controls** (language, appearance) show the selected option as a raised chip with a border and a heavier weight, not by colour alone, and expose `aria-pressed`. Language options are written in their own language: 中文 (locale `zh-TW`, Traditional Chinese, Taiwan) / EN, with accessible names 中文 / English.
- **Forms:** visible labels bound with `for`/`id`, and hints linked through `aria-describedby`. Validation runs on submit and then live: `aria-invalid`, a red border plus an icon and a message, and focus moves to the first invalid field. Native browser validation bubbles are disabled (`novalidate`) because they would appear in the browser's language, not the app's.
- **Secrets** are masked by default with explicit Reveal/Hide (`aria-pressed`) and Copy. They are revealed as text content only and hidden again after 30 s or on lock. Newly generated passwords follow the same rule.
- **Password settings** (`shared/password-options.ts`): a preset select (Default, Strong, Custom), a length slider paired with a number box, four type checkboxes, an "Allowed symbols" field shown only while Symbols is on, and "More options" (look-alike characters, one of each type) behind a disclosure. Problems appear as one plain sentence that says what to change; Generate and Save stay disabled until it is fixed. No bit counts or strength meters are shown. On the Generators page, Generate shows a masked preview and "Save to vault" stores exactly that value (the hint under the button says so, or says to generate first); Saving… replaces the label while it runs. After any settings change an outdated preview is replaced by a short note asking to generate again. In the Login and Secret forms the same panel opens inline from Generate: generate, check, then "Use this password", which applies the value on screen. Cancel leaves the field as it was, and Enter in a settings field never submits the item form.
- **Destructive actions** (delete item, discard stored vault) use an in-app modal `<dialog>` with a danger icon, a plain-language consequence and Cancel focused first. Escape cancels; locking closes it.
- **Popups:** the New-item menu is `position: fixed`, placed from its button's viewport rect, so no scrolling/clipping pane can cut it off. It opens down or up (whichever fits), is capped to the viewport with its own scroll, and closes on resize, outside scroll, outside click, Escape or Tab. The confirmation dialog uses the native modal top layer; toasts are viewport-fixed.
- **Touch:** on `pointer: coarse`, buttons, nav items, menu items and the language/appearance segments are at least 44×44px. That rule sits last in `components.css` so later component rules cannot shrink it; E2E measures it at 320 and 390px in both locales.
- **Feedback:** inline callouts (info, warning, danger, success) with an icon and text, and short-lived toasts in a polite live region. Errors are localized and never show raw low-level messages.
- **States:** loading (spinner plus text, static under reduced motion), core failed to start (with a reload action), start, stored vault found, ephemeral key lost, locked, empty vault (a grid of item types to create), no search matches (clear filters), and stale tab (blocking warning plus reload).
- **Password vault (M4):** the start screen leads with the password vault card and keeps the demo below it, labelled "Demo vault". Card states:
  - create (password, repeat, hint "at least 15 characters");
  - recovery code (shown once in 14 monospace groups, Copy, an "I've saved it" checkbox, then typed back);
  - unlock (password with Show/Hide, "Forgot your password?");
  - reset with the recovery code;
  - restore a backup (choose "With its password" or "With the recovery code");
  - delete from this browser (danger zone);
  - "Password vaults need a secure connection" on plain HTTP.

  Buttons show progress text ("Securing your vault…", "Unlocking…") and stay disabled while the key derivation runs. The Backup page adds "Password and recovery" (change password, new recovery code) and a plain note that these changes don't affect older backups.
- **Motion:** short transitions only. `prefers-reduced-motion: reduce` disables transitions and animations.

## Writing and translation

- Write for people managing credentials: name the goal and the result, not the mechanism. Implementation terms (Rust, WASM, IndexedDB, envelopes, compare-and-swap, key-provider names) belong in `docs/ARCHITECTURE.md`, not on screen. Keep technical terms people need to choose or use something: TOTP, Ed25519, OpenSSH, Base32, otpauth://, hex/base64url, `op`.
- Limitations stay visible and plain, each with its consequence and next step:
  - "Preview version. Do not store real passwords." (預覽版本，請勿存放真實密碼。);
  - experimental password vaults;
  - that no one can reset a lost password and recovery code;
  - data loss on reload for "This session only";
  - failed or blocked saves. Never claim production safety, audits or guaranteed security.

- Catalog keys are grouped by area (`start.*`, `list.*`, `detail.*`, `field.*`, `form.*`, `errors.*`, …). Add a key to `en.ts` first; the build fails until `zh-tw.ts` has it too.
- zh-TW uses Taiwan terminology: 保險庫, 項目, 金鑰, 登入資訊, 產生器, 匯入, 備份, 還原, 設定, 檔案, 剪貼簿 and so on. A unit test rejects common Simplified-only characters.
- Technical identifiers stay as they are in both languages: TOTP, Ed25519, OpenSSH, otpauth://, Base32, hex/base64url, CLI, `op`. User data is never translated.
