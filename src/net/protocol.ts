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

export const WIRE_VERSION = 1 as const;
export const WIRE_ACTION = 'spore-wire-v1';

export const MAX_WIRE_CHARS = 3_000_000;
export const MAX_INVENTORY_IDS = 4_096;
export const MAX_SYNC_PACKETS = 24;
/** A request never exceeds what one response envelope can carry. */
export const MAX_REQUEST_IDS = MAX_SYNC_PACKETS;
export const MAX_SYNC_ID_CHARS = 80;

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

export type SyncMessage = SyncInvMessage | SyncReqMessage | SyncPktMessage;
export type PacketMessage = StemPacketMessage | FluffPacketMessage;
export type WireMessage = SyncMessage | PacketMessage;
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
