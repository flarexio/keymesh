/// <reference lib="webworker" />
/**
 * Password KDF worker: runs the core's `deriveArgon2id` on the WASM module
 * compiled by the page. Handles one request, then the page terminates it.
 * Nothing is logged; errors carry the core's secret-free message only.
 */
import { deriveArgon2id, initSync } from './wasm-pkg/keymesh_wasm';
import type { KdfRequestMessage, KdfResponseMessage } from './kdf-messages';

addEventListener('message', (ev: MessageEvent<KdfRequestMessage>) => {
  let reply: KdfResponseMessage;
  try {
    initSync({ module: ev.data.module });
    const key = deriveArgon2id(ev.data.password, ev.data.request);
    reply = { ok: true, key };
    postMessage(reply, [key.buffer]);
  } catch (e) {
    reply = { ok: false, message: e instanceof Error ? e.message : 'key derivation failed' };
    postMessage(reply);
  }
});
