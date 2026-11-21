/** Page ↔ QR worker protocol. Decoded text is returned only to the page. */
export type QrRequest =
  /** An image file the user chose or pasted (header already checked). */
  | { id: number; kind: 'blob'; blob: Blob }
  /** One camera frame (transferred). */
  | { id: number; kind: 'frame'; bitmap: ImageBitmap };

export type QrResponse =
  | { id: number; ok: true; text: string | null }
  | { id: number; ok: false; reason: 'decode' | 'load' };

/** Longest side the decoder sees; larger images are scaled down first. */
export const QR_DECODE_SIDE = 1600;
