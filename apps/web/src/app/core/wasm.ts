/**
 * Loads the compiled Rust core (crates/keymesh-wasm) once. The `.wasm` file
 * is served from `public/wasm/` by the app's own origin; nothing is fetched
 * from elsewhere.
 */
import init, * as core from './wasm-pkg/keymesh_wasm';

export type Core = typeof core;

let ready: Promise<Core> | null = null;

export function loadCore(): Promise<Core> {
  ready ??= init({
    module_or_path: new URL('wasm/keymesh_wasm_bg.wasm', document.baseURI),
  }).then(() => core);
  return ready;
}
