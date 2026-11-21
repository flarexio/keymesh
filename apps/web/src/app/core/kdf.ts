/**
 * Runs the password KDF (Argon2id, ~0.6 s at the stored parameters) off the
 * main thread, so typing, the lock button and animations stay responsive.
 *
 * - The core chooses and bounds the parameters (`passwordRequest`,
 *   `ProtectedCreation.request`, `beginPasswordChange`); the worker runs the
 *   core's own `deriveArgon2id`, which validates them again before it
 *   allocates memory.
 * - One worker per derivation, terminated afterwards. At most one runs at a
 *   time; `cancel()` terminates it (lock), so a pending result can never
 *   arrive later.
 * - The 32-byte result is transferred, not copied; callers zero it with
 *   `fill(0)` once the core has consumed it. The password itself is a
 *   JavaScript string and cannot be reliably erased (documented limitation).
 */
import { InjectionToken } from '@angular/core';
import type { KdfRequestMessage, KdfResponseMessage } from './kdf-messages';

export class KdfCancelledError extends Error {
  constructor() {
    super('Key derivation was cancelled.');
    this.name = 'KdfCancelledError';
  }
}

export class KdfBusyError extends Error {
  constructor() {
    super('Another unlock is already in progress.');
    this.name = 'KdfBusyError';
  }
}

export interface KdfRunner {
  /** Argon2id(password) for a core-issued request (JSON). */
  derive(password: string, request: string): Promise<Uint8Array>;
  /** Terminate any running derivation; its promise rejects with KdfCancelledError. */
  cancel(): void;
}


/** One derivation in progress (its worker exists once compilation finished). */
interface Job {
  worker: Worker | null;
  cancelled: boolean;
  reject: ((e: unknown) => void) | null;
}

/** Production runner: a module worker running the compiled core. */
export class WorkerKdf implements KdfRunner {
  private module: Promise<WebAssembly.Module> | null = null;
  private job: Job | null = null;

  private compiled(): Promise<WebAssembly.Module> {
    this.module ??= WebAssembly.compileStreaming(
      fetch(new URL('wasm/keymesh_wasm_bg.wasm', document.baseURI)),
    ).catch((e) => {
      this.module = null;
      throw e;
    });
    return this.module;
  }

  async derive(password: string, request: string): Promise<Uint8Array> {
    if (this.job) throw new KdfBusyError();
    const job: Job = { worker: null, cancelled: false, reject: null };
    this.job = job;
    try {
      const module = await this.compiled();
      if (job.cancelled) throw new KdfCancelledError();
      return await new Promise<Uint8Array>((resolve, reject) => {
        const worker = new Worker(new URL('./kdf.worker', import.meta.url), { type: 'module' });
        job.worker = worker;
        job.reject = reject;
        worker.onmessage = (ev: MessageEvent<KdfResponseMessage>) => {
          worker.terminate();
          if (ev.data.ok) resolve(ev.data.key);
          else reject(new Error(ev.data.message));
        };
        worker.onerror = () => {
          worker.terminate();
          reject(new Error('key derivation failed'));
        };
        const msg: KdfRequestMessage = { module, password, request };
        worker.postMessage(msg);
      });
    } finally {
      if (this.job === job) this.job = null;
    }
  }

  cancel(): void {
    const job = this.job;
    if (!job) return;
    this.job = null;
    job.cancelled = true;
    job.worker?.terminate();
    job.reject?.(new KdfCancelledError());
  }
}

export const KDF_RUNNER = new InjectionToken<KdfRunner>('keymesh.kdf-runner', {
  providedIn: 'root',
  factory: () => new WorkerKdf(),
});
