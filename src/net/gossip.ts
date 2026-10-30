/**
 * Set reconciliation / anti-entropy.
 *
 * Two peers never flood their full packet sets at each other. On connect (and
 * periodically) each sends a bounded SYNC_INV inventory of packet ids. The
 * receiver diffs that against local ids and asks for only what it lacks with
 * SYNC_REQ. The responder answers with SYNC_PKT, and every packet is verified
 * again at this boundary before it reaches storage.
 */

import { bytesToHex } from '../crypto/encoding';
import {
  verifyPacket,
  type PacketVerificationResult,
  type SporePacket,
} from '../crypto/packet';
import {
  MAX_INVENTORY_IDS,
  MAX_REQUEST_IDS,
  MAX_SYNC_PACKETS,
  encodeWireMessage,
  isPacketId,
  type SyncInvMessage,
  type SyncPktMessage,
  type SyncReqMessage,
  type WireMessage,
} from './protocol';
import type { Telemetry } from './telemetry';
import type { OutboundMesh } from './transport';

export const DEFAULT_SYNC_INTERVAL_MS = 45_000;
export const DEFAULT_MAX_INVENTORY_IDS = MAX_INVENTORY_IDS;
export const DEFAULT_MAX_REQUEST_IDS = MAX_REQUEST_IDS;
/** Sync sessions older than this are abandoned and pruned. */
export const DEFAULT_SYNC_TTL_MS = 120_000;
export const DEFAULT_MAX_SYNC_SESSIONS = 64;

export interface GossipAppendResult {
  readonly accepted: boolean;
  readonly added: boolean;
  readonly reason?: string;
  readonly detail?: string;
}

export interface GossipStore {
  packetsSnapshot(): readonly SporePacket[];
  get(id: string): SporePacket | undefined;
  append(candidate: unknown): GossipAppendResult;
}

export interface GossipOptions {
  readonly transport: OutboundMesh;
  readonly store: GossipStore;
  readonly telemetry?: Telemetry;
  /** Minimum work accepted from the network. Default 0 (crypto gates only). */
  readonly minPowBits?: number;
  readonly maxInventoryIds?: number;
  readonly maxRequestIds?: number;
  /** Periodic anti-entropy interval. `null` disables the timer. */
  readonly autoSyncMs?: number | null;
  /** Abandon an unfinished sync session after this many milliseconds. */
  readonly syncTtlMs?: number;
  /** Hard cap on concurrent inbound sync sessions. */
  readonly maxSyncSessions?: number;
  readonly now?: () => number;
  readonly randomSid?: () => string;
  /** Called once per newly stored packet (used by the UI to redraw). */
  readonly onAccepted?: (packet: SporePacket) => void;
  /** Injected for tests. Defaults to `verifyPacket`. */
  readonly verify?: (packet: unknown) => PacketVerificationResult;
}

interface SyncState {
  readonly peerId: string;
  readonly sid: string;
  readonly pending: string[];
  requested: number;
  received: number;
  added: number;
  rejected: number;
  duplicates: number;
  readonly startedAt: number;
}

function defaultSid(): string {
  const bytes = new Uint8Array(8);
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi?.getRandomValues === 'function') {
    cryptoApi.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }
  return bytesToHex(bytes);
}

function validLimit(value: number, label: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || value < 1 || value > maximum) {
    throw new RangeError(`${label} must be an integer between 1 and ${maximum}`);
  }
  return value;
}

/**
 * Remote ids this node lacks. Order follows the remote inventory and duplicate
 * ids collapse, so both sides converge deterministically.
 */
export function diffInventories(
  localIds: Iterable<string>,
  remoteIds: readonly string[],
): string[] {
  const local = new Set<string>();
  for (const id of localIds) {
    if (isPacketId(id)) local.add(id);
  }
  const missing: string[] = [];
  const seen = new Set<string>();
  for (const id of remoteIds) {
    if (!isPacketId(id) || local.has(id) || seen.has(id)) continue;
    seen.add(id);
    missing.push(id);
  }
  return missing;
}

export class GossipEngine {
  private readonly transport: OutboundMesh;
  private readonly store: GossipStore;
  private readonly telemetry: Telemetry | undefined;
  private readonly minPowBits: number;
  private readonly maxInventoryIds: number;
  private readonly maxRequestIds: number;
  private readonly autoSyncMs: number | null;
  private readonly syncTtlMs: number;
  private readonly maxSyncSessions: number;
  private readonly now: () => number;
  private readonly randomSid: () => string;
  private readonly onAccepted: ((packet: SporePacket) => void) | undefined;
  private readonly verify: (packet: unknown) => PacketVerificationResult;

  private readonly syncs = new Map<string, SyncState>();
  private readonly lastSyncAt = new Map<string, number>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private running = false;

  constructor(options: GossipOptions) {
    this.transport = options.transport;
    this.store = options.store;
    this.telemetry = options.telemetry;
    this.minPowBits = options.minPowBits ?? 0;
    this.maxInventoryIds = validLimit(
      options.maxInventoryIds ?? DEFAULT_MAX_INVENTORY_IDS,
      'maxInventoryIds',
      MAX_INVENTORY_IDS,
    );
    this.maxRequestIds = validLimit(
      options.maxRequestIds ?? DEFAULT_MAX_REQUEST_IDS,
      'maxRequestIds',
      MAX_REQUEST_IDS,
    );
    this.autoSyncMs =
      options.autoSyncMs === null
        ? null
        : options.autoSyncMs ?? DEFAULT_SYNC_INTERVAL_MS;
    if (this.autoSyncMs !== null && this.autoSyncMs < 1_000) {
      throw new RangeError('autoSyncMs must be at least 1000 or null');
    }
    this.syncTtlMs = options.syncTtlMs ?? DEFAULT_SYNC_TTL_MS;
    if (!Number.isSafeInteger(this.syncTtlMs) || this.syncTtlMs < 1_000) {
      throw new RangeError('syncTtlMs must be an integer of at least 1000');
    }
    this.maxSyncSessions = options.maxSyncSessions ?? DEFAULT_MAX_SYNC_SESSIONS;
    if (!Number.isSafeInteger(this.maxSyncSessions) || this.maxSyncSessions < 1) {
      throw new RangeError('maxSyncSessions must be a positive integer');
    }
    if (!Number.isSafeInteger(this.minPowBits) || this.minPowBits < 0 || this.minPowBits > 64) {
      throw new RangeError('minPowBits must be between 0 and 64');
    }
    this.now = options.now ?? Date.now;
    this.randomSid = options.randomSid ?? defaultSid;
    this.onAccepted = options.onAccepted;
    this.verify =
      options.verify ??
      ((packet: unknown) =>
        verifyPacket(packet, this.minPowBits > 0 ? { minPowBits: this.minPowBits } : {}));
  }

  /** Start periodic anti-entropy. Safe to call more than once. */
  start(): void {
    if (this.running) return;
    this.running = true;
    if (this.autoSyncMs === null) return;
    this.timer = setInterval(() => {
      const now = this.now();
      this.pruneStaleSessions(now);
      for (const peerId of this.transport.peerIds()) {
        const last = this.lastSyncAt.get(peerId) ?? 0;
        if (now - last >= this.autoSyncMs!) this.syncWith(peerId);
      }
    }, this.autoSyncMs);
    const maybeUnref = this.timer as unknown as { unref?: () => void };
    maybeUnref.unref?.();
  }

  stop(): void {
    this.running = false;
    if (this.timer !== null) {
      clearInterval(this.timer);
      this.timer = null;
    }
    this.syncs.clear();
  }

  inventory(): string[] {
    const ids = this.store
      .packetsSnapshot()
      .map((packet) => packet.id)
      .filter(isPacketId);
    ids.sort();
    return ids.slice(0, this.maxInventoryIds);
  }

  onPeerJoin(peerId: string): void {
    this.syncWith(peerId);
  }

  onPeerLeave(peerId: string): void {
    this.lastSyncAt.delete(peerId);
    const prefix = `${peerId}:`;
    for (const key of [...this.syncs.keys()]) {
      if (key.startsWith(prefix)) this.syncs.delete(key);
    }
  }

  /** Kick off an inventory exchange with one peer. */
  syncWith(peerId: string): void {
    if (!this.transport.peerIds().includes(peerId)) return;
    this.pruneStaleSessions(this.now());
    const sid = this.randomSid();
    this.lastSyncAt.set(peerId, this.now());
    const message: SyncInvMessage = {
      v: 1,
      t: 'SYNC_INV',
      sid,
      ids: this.inventory(),
    };
    void this.send(peerId, encodeWireMessage(message)).then((sent) => {
      if (!sent) {
        this.telemetry?.emit('sync:complete', {
          peerId,
          sid,
          requested: 0,
          received: 0,
          added: 0,
          rejected: 0,
          duplicates: 0,
          ok: false,
        });
      }
    });
  }

  /** Returns false when the message is not a gossip message. */
  handleMessage(peerId: string, message: WireMessage): boolean {
    switch (message.t) {
      case 'SYNC_INV':
        this.handleInventory(peerId, message);
        return true;
      case 'SYNC_REQ':
        this.handleRequest(peerId, message);
        return true;
      case 'SYNC_PKT':
        this.handlePackets(peerId, message);
        return true;
      default:
        return false;
    }
  }

  private syncKey(peerId: string, sid: string): string {
    return `${peerId}:${sid}`;
  }

  private handleInventory(peerId: string, message: SyncInvMessage): void {
    const key = this.syncKey(peerId, message.sid);
    if (this.syncs.has(key)) return;
    if (this.syncs.size >= this.maxSyncSessions) {
      this.pruneStaleSessions(this.now(), true);
      if (this.syncs.size >= this.maxSyncSessions) {
        this.telemetry?.emit('pkt:drop', {
          peerId,
          sid: message.sid,
          reason: 'sync-capacity',
        });
        return;
      }
    }
    const missing = diffInventories(this.inventory(), message.ids);
    const state: SyncState = {
      peerId,
      sid: message.sid,
      pending: missing,
      requested: 0,
      received: 0,
      added: 0,
      rejected: 0,
      duplicates: 0,
      startedAt: this.now(),
    };
    this.syncs.set(key, state);
    this.dispatchNext(state);
  }

  private dispatchNext(state: SyncState): void {
    const batch: string[] = [];
    while (batch.length < this.maxRequestIds && state.pending.length > 0) {
      const id = state.pending.shift();
      if (id !== undefined && this.store.get(id) === undefined) batch.push(id);
    }
    if (batch.length === 0) {
      this.finish(state);
      return;
    }
    state.requested += batch.length;
    const message: SyncReqMessage = {
      v: 1,
      t: 'SYNC_REQ',
      sid: state.sid,
      ids: batch,
    };
    void this.send(state.peerId, encodeWireMessage(message)).then((sent) => {
      if (!sent) this.finish(state);
    });
  }

  private handleRequest(peerId: string, message: SyncReqMessage): void {
    // The parser already caps ids at MAX_REQUEST_IDS; enforce the same bound
    // here so a response always fits one SYNC_PKT envelope.
    const packets: SporePacket[] = [];
    for (const id of message.ids.slice(0, MAX_SYNC_PACKETS)) {
      const packet = this.store.get(id);
      if (packet !== undefined) packets.push(packet);
    }
    const reply: SyncPktMessage = {
      v: 1,
      t: 'SYNC_PKT',
      sid: message.sid,
      packets,
    };
    void this.send(peerId, encodeWireMessage(reply));
  }

  private handlePackets(peerId: string, message: SyncPktMessage): void {
    const key = this.syncKey(peerId, message.sid);
    const state = this.syncs.get(key);
    let received = 0;
    let added = 0;
    let rejected = 0;
    let duplicates = 0;

    for (const candidate of message.packets) {
      received += 1;
      const verified = this.verify(candidate);
      if (!verified.ok) {
        rejected += 1;
        const id = this.idHint(candidate);
        this.telemetry?.emit('pkt:drop', {
          id,
          peerId,
          reason: 'invalid-packet',
          detail: `${verified.reason}: ${verified.detail}`,
        });
        continue;
      }

      const result = this.store.append(verified.packet);
      if (!result.accepted) {
        if (result.reason !== 'duplicate') {
          rejected += 1;
          this.telemetry?.emit('pkt:drop', {
            id: verified.packet.id,
            peerId,
            reason: result.reason ?? 'rejected',
            detail: result.detail ?? '',
          });
        } else {
          duplicates += 1;
        }
        continue;
      }
      if (result.added) {
        added += 1;
        this.onAccepted?.(verified.packet);
      } else {
        duplicates += 1;
      }
    }

    if (state !== undefined) {
      state.received += received;
      state.added += added;
      state.rejected += rejected;
      state.duplicates += duplicates;
      this.dispatchNext(state);
      return;
    }

    this.telemetry?.emit('sync:complete', {
      peerId,
      sid: message.sid,
      requested: 0,
      received,
      added,
      rejected,
      duplicates,
      ok: rejected === 0,
    });
  }

  /**
   * Abandon unfinished sessions past their TTL. When `force` is set, also drop
   * the oldest sessions until at least one free slot exists.
   */
  private pruneStaleSessions(now: number, force = false): void {
    for (const [key, state] of [...this.syncs]) {
      if (now - state.startedAt < this.syncTtlMs) continue;
      this.syncs.delete(key);
      this.telemetry?.emit('sync:complete', {
        peerId: state.peerId,
        sid: state.sid,
        requested: state.requested,
        received: state.received,
        added: state.added,
        rejected: state.rejected,
        duplicates: state.duplicates,
        ok: false,
        reason: 'timeout',
      });
    }
    if (!force) return;
    while (this.syncs.size >= this.maxSyncSessions) {
      const oldestKey = this.syncs.keys().next().value;
      if (oldestKey === undefined) return;
      const state = this.syncs.get(oldestKey);
      this.syncs.delete(oldestKey);
      if (state === undefined) continue;
      this.telemetry?.emit('sync:complete', {
        peerId: state.peerId,
        sid: state.sid,
        requested: state.requested,
        received: state.received,
        added: state.added,
        rejected: state.rejected,
        duplicates: state.duplicates,
        ok: false,
        reason: 'capacity',
      });
    }
  }

  /** Send without letting a transport rejection escape as an unhandled promise. */
  private async send(peerId: string, data: string): Promise<boolean> {
    try {
      return await this.transport.send(peerId, data);
    } catch {
      return false;
    }
  }

  private finish(state: SyncState): void {
    const key = this.syncKey(state.peerId, state.sid);
    if (!this.syncs.has(key)) return;
    this.syncs.delete(key);
    this.telemetry?.emit('sync:complete', {
      peerId: state.peerId,
      sid: state.sid,
      requested: state.requested,
      received: state.received,
      added: state.added,
      rejected: state.rejected,
      duplicates: state.duplicates,
      ok: state.rejected === 0,
    });
  }

  private idHint(candidate: unknown): string {
    if (typeof candidate === 'object' && candidate !== null && 'id' in candidate) {
      const id = (candidate as { id?: unknown }).id;
      if (typeof id === 'string' && id.length <= 80) return id;
    }
    return 'unknown';
  }
}
