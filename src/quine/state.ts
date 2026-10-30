/**
 * Quine state codec.
 *
 * A SPORE snapshot carries its packet set inside the document itself as
 * `<script id="spore-quine-state" type="application/json">`. The payload is an
 * LZ-string Base64 blob, which is JSON-safe and, critically, can never contain
 * the byte sequence `</script` (the alphabet is A-Z a-z 0-9 + / =).
 */

import { compressToBase64, decompressFromBase64 } from 'lz-string';
import { verifyPacket, type SporePacket } from '../crypto/packet';

export const QUINE_STATE_ID = 'spore-quine-state';
export const QUINE_STATE_VERSION = 1 as const;
export const QUINE_CODEC = 'lz-string-base64' as const;

/** Hard ceiling on an embedded state document (16 MB of envelope text). */
export const MAX_QUINE_STATE_CHARS = 16_000_000;

export interface QuineEnvelope {
  readonly v: typeof QUINE_STATE_VERSION;
  readonly codec: typeof QUINE_CODEC;
  readonly created_at: number;
  /** Number of packets encoded before verification. */
  readonly count: number;
  /** `compressToBase64(JSON.stringify(packets))`. */
  readonly payload: string;
}

export interface QuineDecodedState {
  readonly createdAt: number;
  readonly packets: SporePacket[];
  /** Packets dropped because id/PoW/Schnorr verification failed. */
  readonly rejected: number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function assertSafeTimestamp(value: unknown, label: string): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a non-negative integer`);
  }
  return value;
}

/**
 * Serialize packets into the JSON text of the quine state script.
 * Ordering is canonical (by id) so identical packet sets produce identical HTML.
 */
export function encodeQuineState(
  packets: Iterable<SporePacket>,
  options: { createdAt?: number } = {},
): string {
  const unique = new Map<string, SporePacket>();
  for (const packet of packets) unique.set(packet.id, packet);
  const sorted = [...unique.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));

  const createdAt = options.createdAt ?? Date.now();
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw new RangeError('createdAt must be a non-negative integer');
  }

  const payload = compressToBase64(JSON.stringify(sorted));
  if (payload.length === 0) throw new Error('LZ compression produced an empty payload');

  const envelope: QuineEnvelope = {
    v: QUINE_STATE_VERSION,
    codec: QUINE_CODEC,
    created_at: createdAt,
    count: sorted.length,
    payload,
  };
  return JSON.stringify(envelope);
}

/**
 * Decode and *verify* embedded state. Invalid packets are counted and dropped
 * rather than trusted; malformed envelopes fail closed.
 */
export function decodeQuineState(text: string): QuineDecodedState {
  if (typeof text !== 'string' || text.length === 0) {
    throw new TypeError('Quine state is empty');
  }
  if (text.length > MAX_QUINE_STATE_CHARS) {
    throw new RangeError('Quine state exceeds the 16 MB ceiling');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new TypeError('Quine state is not valid JSON');
  }
  if (!isRecord(parsed)) throw new TypeError('Quine state must be an object');
  for (const key of Object.keys(parsed)) {
    if (!['v', 'codec', 'created_at', 'count', 'payload'].includes(key)) {
      throw new TypeError(`Unknown quine state field: ${key}`);
    }
  }
  if (parsed['v'] !== QUINE_STATE_VERSION) throw new TypeError('Unsupported quine state version');
  if (parsed['codec'] !== QUINE_CODEC) throw new TypeError('Unsupported quine state codec');

  const createdAt = assertSafeTimestamp(parsed['created_at'], 'Quine created_at');
  const count = parsed['count'];
  if (typeof count !== 'number' || !Number.isSafeInteger(count) || count < 0) {
    throw new TypeError('Quine count must be a non-negative integer');
  }
  const payload = parsed['payload'];
  if (
    typeof payload !== 'string' ||
    payload.length === 0 ||
    !/^[A-Za-z0-9+/=]+$/.test(payload)
  ) {
    throw new TypeError('Quine payload is not valid Base64');
  }

  let decompressed: string | null;
  try {
    decompressed = decompressFromBase64(payload);
  } catch {
    throw new TypeError('Quine payload could not be decompressed');
  }
  if (decompressed === null || decompressed.length === 0) {
    throw new TypeError('Quine payload decompressed to nothing');
  }

  let list: unknown;
  try {
    list = JSON.parse(decompressed);
  } catch {
    throw new TypeError('Quine payload is not valid JSON');
  }
  if (!Array.isArray(list)) throw new TypeError('Quine payload must be a packet array');
  if (list.length !== count) throw new TypeError('Quine count does not match its payload');

  const packets: SporePacket[] = [];
  let rejected = 0;
  for (const candidate of list) {
    const result = verifyPacket(candidate);
    if (result.ok) packets.push(result.packet);
    else rejected += 1;
  }

  return { createdAt, packets, rejected };
}

/** Read the seed document from the live DOM, if present. Never throws. */
export function readQuineStateFromDocument(doc?: Document | null): string | null {
  try {
    // `undefined` means "use the global document"; an explicit null disables
    // DOM seeding (useful for tests and for embedded/worker contexts).
    const target =
      doc === undefined ? (typeof document === 'undefined' ? null : document) : doc;
    if (target === null) return null;
    const element = target.getElementById(QUINE_STATE_ID);
    if (element === null) return null;
    const text = (element.textContent ?? '').trim();
    return text.length === 0 ? null : text;
  } catch {
    return null;
  }
}
