/**
 * Byte/hex/UTF-8 primitives shared by the SPORE crypto kernel.
 *
 * Everything here is synchronous and dependency-light on purpose: SPORE runs
 * from `file://`, `content://` and mobile document viewers where WebCrypto
 * (`crypto.subtle`) is frequently unavailable or origin-gated.
 */

const HEX_RE = /^[0-9a-fA-F]*$/;
const encoder = new TextEncoder();

export function isHex(value: unknown, byteLength?: number): value is string {
  if (typeof value !== 'string' || value.length % 2 !== 0 || !HEX_RE.test(value)) {
    return false;
  }
  return byteLength === undefined || value.length === byteLength * 2;
}

export function assertHex(value: unknown, byteLength: number, label: string): string {
  if (!isHex(value, byteLength)) {
    throw new TypeError(`${label} must be ${byteLength} bytes of hex (${byteLength * 2} characters)`);
  }
  return value.toLowerCase();
}

export function bytesToHex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  if (!isHex(hex)) {
    throw new TypeError('Expected an even-length hex string');
  }
  const normalized = hex.toLowerCase();
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function utf8ToBytes(text: string): Uint8Array {
  return encoder.encode(text);
}

/** UTF-8 byte length (encoding cost is linear and allocation is unavoidable). */
export function utf8ByteLength(text: string): number {
  return encoder.encode(text).length;
}
