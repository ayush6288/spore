/**
 * Hashcash-style proof of work over SHA-256.
 *
 * SPORE's Sybil resistance is a plain leading-zero-bits puzzle on the packet
 * id. Mining is sliced across macrotasks so a 20-bit packet does not freeze
 * the tab, and the yielder deliberately prefers MessageChannel over
 * setTimeout: background tabs clamp timers to 1s, which would make mining
 * crawl exactly when a user queues a post and switches apps.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, isHex } from './encoding';

export const MAX_POW_BITS = 64;
export const MAX_NONCE = 0xffff_ffff;

/** Number of leading zero bits in a byte string (big-endian bit order). */
export function countLeadingZeroBits(bytes: Uint8Array): number {
  let bits = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    return bits;
  }
  return bits;
}

/** Number of leading zero bits in a 32-byte hex digest. */
export function countLeadingZeroBitsHex(hex: string): number {
  if (!isHex(hex, 32)) {
    throw new TypeError('Expected a 32-byte hex digest');
  }
  let bits = 0;
  for (let i = 0; i < hex.length; i += 2) {
    const byte = Number.parseInt(hex.slice(i, i + 2), 16);
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    return bits;
  }
  return bits;
}

export interface HashcashVerification {
  readonly valid: boolean;
  readonly leadingZeroBits: number;
  readonly requiredBits: number;
}

export function verifyHashcash(digest: Uint8Array | string, requiredBits: number): HashcashVerification {
  assertPowBits(requiredBits);
  if (digest instanceof Uint8Array && digest.length !== 32) {
    throw new TypeError('Hashcash digest must be 32 bytes');
  }
  const leadingZeroBits =
    typeof digest === 'string' ? countLeadingZeroBitsHex(digest) : countLeadingZeroBits(digest);
  return {
    valid: leadingZeroBits >= requiredBits,
    leadingZeroBits,
    requiredBits,
  };
}

export interface MiningProgress {
  readonly attempts: number;
  readonly nonce: number;
  readonly elapsedMs: number;
  readonly hashesPerSecond: number;
}

export interface MineHashcashOptions {
  /** Required leading zero bits. 12 bits ≈ 4k attempts, 20 bits ≈ 1M. */
  readonly bits: number;
  /** Map a uint32 nonce to a 32-byte digest. */
  readonly hash: (nonce: number) => Uint8Array;
  readonly nonceStart?: number;
  readonly maxNonce?: number;
  readonly signal?: AbortSignal;
  readonly chunkSize?: number;
  readonly onProgress?: (progress: MiningProgress) => void;
  /** Injectable scheduler, used by tests and by worker hosts. */
  readonly yieldControl?: () => Promise<void>;
}

export interface HashcashResult {
  readonly nonce: number;
  readonly id: string;
  readonly digest: Uint8Array;
  readonly tries: number;
  readonly leadingZeroBits: number;
  readonly elapsedMs: number;
}

export class PowAbortedError extends Error {
  override readonly name = 'AbortError';

  constructor(message = 'Proof-of-work mining aborted') {
    super(message);
  }
}

export class PowExhaustedError extends RangeError {
  override readonly name = 'PowExhaustedError';

  constructor(message = 'Hashcash nonce space exhausted') {
    super(message);
  }
}

function assertPowBits(bits: number): void {
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > MAX_POW_BITS) {
    throw new RangeError(`PoW bits must be an integer between 0 and ${MAX_POW_BITS}`);
  }
}

function now(): number {
  return typeof performance !== 'undefined' && typeof performance.now === 'function'
    ? performance.now()
    : Date.now();
}

/*
 * Shared yield pump. One MessageChannel is reused for every slice; queued
 * resolvers fire one per posted message. Node keeps the process alive for open
 * ports, so both ends are unref'd where that API exists.
 */
type YieldResolver = () => void;
const yieldQueue: YieldResolver[] = [];
let yieldChannel: MessageChannel | null = null;

function unrefPort(port: MessagePort): void {
  const maybeNodePort = port as MessagePort & { unref?: () => void };
  maybeNodePort.unref?.();
}

function ensureYieldChannel(): MessageChannel {
  if (yieldChannel !== null) return yieldChannel;
  const channel = new MessageChannel();
  channel.port1.onmessage = () => {
    const resolve = yieldQueue.shift();
    resolve?.();
  };
  unrefPort(channel.port1);
  unrefPort(channel.port2);
  yieldChannel = channel;
  return channel;
}

const IS_NODE =
  typeof process !== 'undefined' &&
  typeof process.versions === 'object' &&
  typeof process.versions.node === 'string';

/** Yield to the event loop without browser timer clamping. */
export function yieldToEventLoop(): Promise<void> {
  if (IS_NODE) {
    // A live timer/immediate keeps a CLI miner alive until it finds a nonce.
    return new Promise<void>((resolve) => {
      if (typeof setImmediate === 'function') setImmediate(resolve);
      else setTimeout(resolve, 0);
    });
  }
  if (typeof MessageChannel === 'undefined') {
    return new Promise<void>((resolve) => {
      setTimeout(resolve, 0);
    });
  }
  const channel = ensureYieldChannel();
  return new Promise<void>((resolve) => {
    yieldQueue.push(resolve);
    channel.port2.postMessage(0);
  });
}

const TARGET_SLICE_MS = 6;
const MIN_CHUNK = 256;
const MAX_CHUNK = 65_536;

/**
 * Mine a nonce whose digest has at least `bits` leading zero bits.
 *
 * The scan is deterministic from `nonceStart`, resumable by passing the last
 * observed nonce back in, and cooperatively cancellable via AbortSignal.
 */
export async function mineHashcash(options: MineHashcashOptions): Promise<HashcashResult> {
  const { bits, hash, signal, onProgress } = options;
  assertPowBits(bits);

  const nonceStart = options.nonceStart ?? 0;
  const maxNonce = options.maxNonce ?? MAX_NONCE;
  if (!Number.isSafeInteger(nonceStart) || nonceStart < 0 || nonceStart > MAX_NONCE) {
    throw new RangeError('nonceStart must be a uint32');
  }
  if (!Number.isSafeInteger(maxNonce) || maxNonce < nonceStart || maxNonce > MAX_NONCE) {
    throw new RangeError('maxNonce must be a uint32 greater than or equal to nonceStart');
  }

  const yieldControl = options.yieldControl ?? yieldToEventLoop;
  let chunk = Math.min(Math.max(options.chunkSize ?? 4096, MIN_CHUNK), MAX_CHUNK);
  let nonce = nonceStart;
  let attempts = 0;
  const startedAt = now();

  for (;;) {
    if (signal?.aborted) throw new PowAbortedError();

    const sliceStarted = now();
    for (let i = 0; i < chunk; i += 1) {
      if (nonce > maxNonce) {
        throw new PowExhaustedError(`No nonce with ${bits} leading zero bits in range`);
      }

      const digest = hash(nonce);
      if (digest.length !== 32) {
        throw new TypeError('Hashcash hash function must return 32 bytes');
      }
      attempts += 1;

      const leadingZeroBits = countLeadingZeroBits(digest);
      if (leadingZeroBits >= bits) {
        return {
          nonce,
          id: bytesToHex(digest),
          digest,
          tries: attempts,
          leadingZeroBits,
          elapsedMs: now() - startedAt,
        };
      }
      nonce += 1;
    }

    const sliceMs = Math.max(now() - sliceStarted, 0.001);
    if (sliceMs < TARGET_SLICE_MS) {
      chunk = Math.min(chunk * 2, MAX_CHUNK);
    } else if (sliceMs > TARGET_SLICE_MS * 2.5) {
      chunk = Math.max(Math.floor(chunk / 2), MIN_CHUNK);
    }

    if (onProgress !== undefined) {
      const elapsedMs = now() - startedAt;
      onProgress({
        attempts,
        nonce,
        elapsedMs,
        hashesPerSecond: elapsedMs > 0 ? Math.round((attempts / elapsedMs) * 1000) : 0,
      });
    }

    if (signal?.aborted) throw new PowAbortedError();
    await yieldControl();
  }
}

/** Convenience wrapper: mine SHA-256 over a caller-supplied byte prefix. */
export function mineSha256(
  prefix: Uint8Array,
  bits: number,
  options: Omit<MineHashcashOptions, 'bits' | 'hash'> = {},
): Promise<HashcashResult> {
  return mineHashcash({
    ...options,
    bits,
    hash: (nonce) => {
      const nonceBytes = new Uint8Array(4);
      new DataView(nonceBytes.buffer).setUint32(0, nonce, false);
      const payload = new Uint8Array(prefix.length + 4);
      payload.set(prefix, 0);
      payload.set(nonceBytes, prefix.length);
      return sha256(payload);
    },
  });
}
