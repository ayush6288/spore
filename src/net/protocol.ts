/**
 * SPORE mesh wire protocol v1.
 *
 * Every DataChannel message is a UTF-8 JSON envelope. There are five types:
 *
 *   SYNC_INV  — compact inventory: packet ids this peer already has
 *   SYNC_REQ  — ids the sender is missing
 *   SYNC_PKT  — verified-on-arrival packets answering a SYNC_REQ
 *   PKT_STEM  — one Dandelion stem hop
 *   PKT_FLUFF — a packet entering the public fluff phase
 *
 * Parsing is deliberately strict and size-bounded. Cryptographic packet
 * verification happens after parsing, at the gossip/Dandelion boundary.
 */

import { isHex } from '../crypto/encoding';
import { validateMediaManifest, type MediaManifest } from '../crypto/packet';

export const WIRE_VERSION = 1 as const;
export const WIRE_ACTION = 'spore-wire-v1';

export const MAX_WIRE_CHARS = 3_000_000;
export const MAX_INVENTORY_IDS = 4_096;
export const MAX_SYNC_PACKETS = 24;
/** A request never exceeds what one response envelope can carry. */
export const MAX_REQUEST_IDS = MAX_SYNC_PACKETS;
export const MAX_SYNC_ID_CHARS = 80;

/** Media request windows are deliberately small: 4-6 chunks per round trip. */
export const MAX_MEDIA_REQUEST_CHUNKS = 6;
export const MAX_MEDIA_HAVE_CHUNKS = 8_192;
export const MAX_MEDIA_CHUNK_B64_CHARS = 90_000;
const BASE64_BODY_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const SYNC_ID_RE = /^[A-Za-z0-9_-]{1,80}$/;

export interface SyncInvMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'SYNC_INV';
  readonly sid: string;
  readonly ids: readonly string[];
}

export interface SyncReqMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'SYNC_REQ';
  readonly sid: string;
  readonly ids: readonly string[];
}

export interface SyncPktMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'SYNC_PKT';
  readonly sid: string;
  /** Raw packet objects; each must pass verifyPacket at the boundary. */
  readonly packets: readonly unknown[];
}

export interface StemPacketMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'PKT_STEM';
  readonly packet: unknown;
}

export interface FluffPacketMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'PKT_FLUFF';
  readonly packet: unknown;
}

export interface MediaHaveMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'MEDIA_HAVE';
  readonly media_id: string;
  readonly available_chunks: readonly number[];
  /** Present so a peer can verify chunks without a prior packet fetch. */
  readonly manifest?: MediaManifest;
}

export interface MediaReqMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'MEDIA_REQ';
  readonly media_id: string;
  readonly chunk_indices: readonly number[];
}

export interface MediaChunkMessage {
  readonly v: typeof WIRE_VERSION;
  readonly t: 'MEDIA_CHUNK';
  readonly media_id: string;
  readonly chunk_index: number;
  /** Base64 of one chunk (at most 64 KiB raw, ~87 KiB encoded). */
  readonly data_b64: string;
}

export type SyncMessage = SyncInvMessage | SyncReqMessage | SyncPktMessage;
export type PacketMessage = StemPacketMessage | FluffPacketMessage;
export type MediaMessage = MediaHaveMessage | MediaReqMessage | MediaChunkMessage;
export type WireMessage = SyncMessage | PacketMessage | MediaMessage;
export type WireMessageType = WireMessage['t'];

export type WireParseResult =
  | { readonly ok: true; readonly message: WireMessage }
  | { readonly ok: false; readonly reason: string };

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

export function isPacketId(value: unknown): value is string {
  return isHex(value, 32) && value === value.toLowerCase();
}

function hasOnlyKeys(record: Record<string, unknown>, keys: readonly string[]): boolean {
  const allowed = new Set(keys);
  return Object.keys(record).every((key) => allowed.has(key));
}

function parseSyncId(value: unknown): string | null {
  if (typeof value !== 'string' || !SYNC_ID_RE.test(value)) return null;
  return value;
}

function parseIds(value: unknown, limit: number): string[] | null {
  if (!Array.isArray(value) || value.length > limit) return null;
  const seen = new Set<string>();
  const ids: string[] = [];
  for (const id of value) {
    if (!isPacketId(id)) return null;
    if (!seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
  }
  return ids;
}

function parseChunkIndices(value: unknown, limit: number): number[] | null {
  if (!Array.isArray(value) || value.length === 0 || value.length > limit) return null;
  const seen = new Set<number>();
  const indices: number[] = [];
  for (const candidate of value) {
    if (
      typeof candidate !== 'number' ||
      !Number.isSafeInteger(candidate) ||
      candidate < 0 ||
      candidate >= MAX_MEDIA_HAVE_CHUNKS ||
      seen.has(candidate)
    ) {
      return null;
    }
    seen.add(candidate);
    indices.push(candidate);
  }
  indices.sort((a, b) => a - b);
  return indices;
}

function parseMediaManifestField(value: unknown, mediaId: string): MediaManifest | null {
  try {
    const manifest = validateMediaManifest(value);
    return manifest.media_id === mediaId ? manifest : null;
  } catch {
    return null;
  }
}

/**
 * Parse and structurally validate one mesh message. A successful parse makes
 * no claim about packet authenticity — that is the next gate.
 */
export function parseWireMessage(raw: unknown): WireParseResult {
  if (typeof raw !== 'string' || raw.length === 0) {
    return { ok: false, reason: 'message is not a non-empty string' };
  }
  if (raw.length > MAX_WIRE_CHARS) {
    return { ok: false, reason: `message exceeds ${MAX_WIRE_CHARS} characters` };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, reason: 'message is not valid JSON' };
  }
  if (!isRecord(parsed)) return { ok: false, reason: 'message must be a JSON object' };
  if (parsed['v'] !== WIRE_VERSION) return { ok: false, reason: 'unsupported wire version' };

  const type = parsed['t'];
  if (typeof type !== 'string') return { ok: false, reason: 'message type is missing' };

  if (type === 'SYNC_INV') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'sid', 'ids'])) {
      return { ok: false, reason: 'SYNC_INV has unknown fields' };
    }
    const sid = parseSyncId(parsed['sid']);
    const ids = parseIds(parsed['ids'], MAX_INVENTORY_IDS);
    if (sid === null || ids === null) return { ok: false, reason: 'SYNC_INV is malformed' };
    return { ok: true, message: { v: WIRE_VERSION, t: 'SYNC_INV', sid, ids } };
  }

  if (type === 'SYNC_REQ') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'sid', 'ids'])) {
      return { ok: false, reason: 'SYNC_REQ has unknown fields' };
    }
    const sid = parseSyncId(parsed['sid']);
    const ids = parseIds(parsed['ids'], MAX_REQUEST_IDS);
    if (sid === null || ids === null) return { ok: false, reason: 'SYNC_REQ is malformed' };
    return { ok: true, message: { v: WIRE_VERSION, t: 'SYNC_REQ', sid, ids } };
  }

  if (type === 'SYNC_PKT') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'sid', 'packets'])) {
      return { ok: false, reason: 'SYNC_PKT has unknown fields' };
    }
    const sid = parseSyncId(parsed['sid']);
    const packets = parsed['packets'];
    if (
      sid === null ||
      !Array.isArray(packets) ||
      packets.length > MAX_SYNC_PACKETS ||
      !packets.every((packet) => isRecord(packet))
    ) {
      return { ok: false, reason: 'SYNC_PKT is malformed' };
    }
    return {
      ok: true,
      message: { v: WIRE_VERSION, t: 'SYNC_PKT', sid, packets: packets.slice() },
    };
  }

  if (type === 'PKT_STEM' || type === 'PKT_FLUFF') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'packet'])) {
      return { ok: false, reason: `${type} has unknown fields` };
    }
    const packet = parsed['packet'];
    if (!isRecord(packet)) return { ok: false, reason: `${type} packet is not an object` };
    return {
      ok: true,
      message:
        type === 'PKT_STEM'
          ? { v: WIRE_VERSION, t: 'PKT_STEM', packet }
          : { v: WIRE_VERSION, t: 'PKT_FLUFF', packet },
    };
  }

  if (type === 'MEDIA_HAVE') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'media_id', 'available_chunks', 'manifest'])) {
      return { ok: false, reason: 'MEDIA_HAVE has unknown fields' };
    }
    const mediaId = parsed['media_id'];
    const chunks = parsed['available_chunks'];
    if (!isPacketId(mediaId)) return { ok: false, reason: 'MEDIA_HAVE media_id is malformed' };
    if (!Array.isArray(chunks) || chunks.length > MAX_MEDIA_HAVE_CHUNKS) {
      return { ok: false, reason: 'MEDIA_HAVE available_chunks is malformed' };
    }
    const available = new Set<number>();
    for (const candidate of chunks) {
      if (
        typeof candidate !== 'number' ||
        !Number.isSafeInteger(candidate) ||
        candidate < 0 ||
        candidate >= MAX_MEDIA_HAVE_CHUNKS
      ) {
        return { ok: false, reason: 'MEDIA_HAVE available_chunks is malformed' };
      }
      available.add(candidate);
    }
    let manifest: MediaManifest | undefined;
    if (parsed['manifest'] !== undefined) {
      const parsedManifest = parseMediaManifestField(parsed['manifest'], mediaId);
      if (parsedManifest === null) {
        return { ok: false, reason: 'MEDIA_HAVE manifest is malformed or mismatched' };
      }
      manifest = parsedManifest;
    }
    return {
      ok: true,
      message: {
        v: WIRE_VERSION,
        t: 'MEDIA_HAVE',
        media_id: mediaId,
        available_chunks: [...available].sort((a, b) => a - b),
        ...(manifest !== undefined ? { manifest } : {}),
      },
    };
  }

  if (type === 'MEDIA_REQ') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'media_id', 'chunk_indices'])) {
      return { ok: false, reason: 'MEDIA_REQ has unknown fields' };
    }
    const mediaId = parsed['media_id'];
    if (!isPacketId(mediaId)) return { ok: false, reason: 'MEDIA_REQ media_id is malformed' };
    const indices = parseChunkIndices(parsed['chunk_indices'], MAX_MEDIA_REQUEST_CHUNKS);
    if (indices === null) return { ok: false, reason: 'MEDIA_REQ chunk_indices is malformed' };
    return {
      ok: true,
      message: { v: WIRE_VERSION, t: 'MEDIA_REQ', media_id: mediaId, chunk_indices: indices },
    };
  }

  if (type === 'MEDIA_CHUNK') {
    if (!hasOnlyKeys(parsed, ['v', 't', 'media_id', 'chunk_index', 'data_b64'])) {
      return { ok: false, reason: 'MEDIA_CHUNK has unknown fields' };
    }
    const mediaId = parsed['media_id'];
    const chunkIndex = parsed['chunk_index'];
    const data = parsed['data_b64'];
    if (!isPacketId(mediaId)) return { ok: false, reason: 'MEDIA_CHUNK media_id is malformed' };
    if (
      typeof chunkIndex !== 'number' ||
      !Number.isSafeInteger(chunkIndex) ||
      chunkIndex < 0 ||
      chunkIndex >= MAX_MEDIA_HAVE_CHUNKS
    ) {
      return { ok: false, reason: 'MEDIA_CHUNK chunk_index is malformed' };
    }
    if (
      typeof data !== 'string' ||
      data.length === 0 ||
      data.length > MAX_MEDIA_CHUNK_B64_CHARS ||
      !BASE64_BODY_RE.test(data)
    ) {
      return { ok: false, reason: 'MEDIA_CHUNK data_b64 is malformed' };
    }
    return {
      ok: true,
      message: {
        v: WIRE_VERSION,
        t: 'MEDIA_CHUNK',
        media_id: mediaId,
        chunk_index: chunkIndex,
        data_b64: data,
      },
    };
  }

  return { ok: false, reason: `unknown message type: ${type}` };
}

export function encodeWireMessage(message: WireMessage): string {
  return JSON.stringify(message);
}

export function isSyncMessage(message: WireMessage): message is SyncMessage {
  return message.t === 'SYNC_INV' || message.t === 'SYNC_REQ' || message.t === 'SYNC_PKT';
}

export function isPacketMessage(message: WireMessage): message is PacketMessage {
  return message.t === 'PKT_STEM' || message.t === 'PKT_FLUFF';
}

export function isMediaMessage(message: WireMessage): message is MediaMessage {
  return message.t === 'MEDIA_HAVE' || message.t === 'MEDIA_REQ' || message.t === 'MEDIA_CHUNK';
}
