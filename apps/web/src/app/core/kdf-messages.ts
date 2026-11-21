/** Messages between the page and the KDF worker (no DOM types). */
export interface KdfRequestMessage {
  module: WebAssembly.Module;
  password: string;
  request: string;
}

export type KdfResponseMessage = { ok: true; key: Uint8Array } | { ok: false; message: string };
