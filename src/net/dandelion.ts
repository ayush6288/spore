/**
 * Dandelion++-style source obfuscation.
 *
 * Local publishes enter the stem phase at hop 0. A stem node forwards to
 * exactly one randomly chosen peer (never the peer it received the packet
 * from). Each receiver increments `hop_count`; the packet flips to fluff when
 * the hop limit is reached, when no further stem peers exist, or with a 30%
 * per-hop probability. Fluff packets are broadcast normally.
 *
 * `hop_count` and `dandelion_phase` are excluded from the signed packet id, so
 * relays can mutate them without invalidating the author's signature.
 */

import {
  MAX_HOP_COUNT,
  verifyPacket,
  type PacketVerificationResult,
  type SporePacket,
} from '../crypto/packet';
import {
  encodeWireMessage,
  type FluffPacketMessage,
  type PacketMessage,
  type StemPacketMessage,
  type WireMessage,
} from './protocol';
import type { Telemetry } from './telemetry';
import type { OutboundMesh } from './transport';

export const DEFAULT_FLUFF_PROBABILITY = 0.3;
export const DEFAULT_MAX_STEM_HOPS = 3;
export const DEFAULT_MAX_SEEN = 4_096;

export interface DandelionAppendResult {
  readonly accepted: boolean;
  readonly added: boolean;
  readonly reason?: string;
  readonly detail?: string;
}

export interface DandelionOptions {
  readonly transport: OutboundMesh;
  readonly ingest: (packet: SporePacket) => DandelionAppendResult;
  readonly has: (id: string) => boolean;
  readonly telemetry?: Telemetry;
  /** Called once per newly stored packet (used by the UI to redraw). */
  readonly onAccepted?: (packet: SporePacket) => void;
  readonly fluffProbability?: number;
  readonly maxHops?: number;
  readonly maxSeen?: number;
  readonly random?: () => number;
  /** Injected for tests. Defaults to `verifyPacket`. */
  readonly verify?: (packet: unknown) => PacketVerificationResult;
}

export interface PublishRoute {
  readonly accepted: boolean;
  readonly added: boolean;
  readonly phase: 'stem' | 'fluff';
  /** Stem peer, or null when the packet went straight to fluff. */
  readonly target: string | null;
  readonly reason?: string;
}

export interface PublishOptions {
  /** Skip the stem phase and broadcast fluff immediately (UI toggle). */
  readonly directFluff?: boolean;
}

type IncomingPhase = 'stem' | 'fluff';

function randomIndex(length: number, random: () => number): number {
  const value = random();
  if (!Number.isFinite(value)) return 0;
  return Math.min(length - 1, Math.max(0, Math.floor(value * length)));
}

/** Choose one element from a known non-empty list. */
function pickOne(peers: readonly string[], random: () => number): string {
  const target = peers[randomIndex(peers.length, random)];
  if (target === undefined) {
    throw new Error('pickOne requires a non-empty peer list');
  }
  return target;
}

export class DandelionRouter {
  private readonly transport: OutboundMesh;
  private readonly ingest: (packet: SporePacket) => DandelionAppendResult;
  private readonly hasStore: (id: string) => boolean;
  private readonly telemetry: Telemetry | undefined;
  private readonly onAccepted: ((packet: SporePacket) => void) | undefined;
  private readonly fluffProbability: number;
  private readonly maxHops: number;
  private readonly maxSeen: number;
  private readonly random: () => number;
  private readonly verify: (packet: unknown) => PacketVerificationResult;
  private readonly seen = new Map<string, true>();

  constructor(options: DandelionOptions) {
    this.transport = options.transport;
    this.ingest = options.ingest;
    this.hasStore = options.has;
    this.telemetry = options.telemetry;
    this.onAccepted = options.onAccepted;
    this.fluffProbability = options.fluffProbability ?? DEFAULT_FLUFF_PROBABILITY;
    if (
      !Number.isFinite(this.fluffProbability) ||
      this.fluffProbability < 0 ||
      this.fluffProbability > 1
    ) {
      throw new RangeError('fluffProbability must be between 0 and 1');
    }
    this.maxHops = options.maxHops ?? DEFAULT_MAX_STEM_HOPS;
    if (
      !Number.isSafeInteger(this.maxHops) ||
      this.maxHops < 1 ||
      this.maxHops > MAX_HOP_COUNT
    ) {
      throw new RangeError(`maxHops must be between 1 and ${MAX_HOP_COUNT}`);
    }
    this.maxSeen = options.maxSeen ?? DEFAULT_MAX_SEEN;
    if (!Number.isSafeInteger(this.maxSeen) || this.maxSeen < 1) {
      throw new RangeError('maxSeen must be a positive integer');
    }
    this.random = options.random ?? Math.random;
    this.verify = options.verify ?? ((packet: unknown) => verifyPacket(packet));
  }

  /**
   * Store and route a locally authored packet. By default it enters at hop 0
   * in stem phase; with no peers it transitions immediately to fluff. Passing
   * `directFluff` broadcasts immediately instead, bypassing stem routing.
   */
  publish(packet: SporePacket, options: PublishOptions = {}): PublishRoute {
    const verified = this.verify(packet);
    if (!verified.ok) {
      this.drop(this.idHint(packet), 'local', 'invalid-packet', verified.detail);
      return {
        accepted: false,
        added: false,
        phase: 'stem',
        target: null,
        reason: verified.reason,
      };
    }

    const directFluff = options.directFluff === true;
    const normalized: SporePacket = {
      ...verified.packet,
      hop_count: 0,
      dandelion_phase: directFluff ? 'fluff' : 'stem',
    };
    const stored = this.store(normalized);
    if (!stored.accepted) {
      return {
        accepted: false,
        added: false,
        phase: normalized.dandelion_phase,
        target: null,
        reason: stored.reason ?? 'rejected',
      };
    }
    if (!stored.added) {
      return {
        accepted: true,
        added: false,
        phase: normalized.dandelion_phase,
        target: null,
        reason: stored.reason ?? 'duplicate',
      };
    }

    this.markSeen(normalized.id);
    const peers = this.transport.peerIds();
    if (directFluff) {
      this.fanout('local', normalized, 'direct-fluff', 0);
      return { accepted: true, added: true, phase: 'fluff', target: null };
    }
    if (peers.length === 0) {
      this.telemetry?.emit('pkt:fluff', {
        id: normalized.id,
        hop: 0,
        peerId: 'local',
        reason: 'no-peers',
        broadcast: 0,
      });
      return { accepted: true, added: true, phase: 'fluff', target: null };
    }

    const target = pickOne(peers, this.random);
    const message: StemPacketMessage = {
      v: 1,
      t: 'PKT_STEM',
      packet: normalized,
    };
    this.telemetry?.emit('pkt:stem', {
      id: normalized.id,
      hop: 0,
      peerId: 'local',
      target,
    });
    void this.send(target, encodeWireMessage(message)).then((sent) => {
      if (!sent) {
        this.telemetry?.emit('pkt:drop', {
          id: normalized.id,
          peerId: target,
          reason: 'send-failed',
        });
      }
    });
    return { accepted: true, added: true, phase: 'stem', target };
  }

  /** Returns false when the message is not a Dandelion packet message. */
  handleMessage(peerId: string, message: WireMessage): boolean {
    if (message.t === 'PKT_STEM') {
      this.handlePacket(peerId, 'stem', message);
      return true;
    }
    if (message.t === 'PKT_FLUFF') {
      this.handlePacket(peerId, 'fluff', message);
      return true;
    }
    return false;
  }

  seenCount(): number {
    return this.seen.size;
  }

  private handlePacket(peerId: string, kind: IncomingPhase, message: PacketMessage): void {
    const verified = this.verify(message.packet);
    if (!verified.ok) {
      this.drop(this.idHint(message.packet), peerId, 'invalid-packet', `${verified.reason}: ${verified.detail}`);
      return;
    }
    const packet = verified.packet;
    if (message.t === 'PKT_STEM' && packet.dandelion_phase !== 'stem') {
      this.drop(packet.id, peerId, 'phase-mismatch', 'PKT_STEM carried a non-stem packet');
      return;
    }
    if (message.t === 'PKT_FLUFF' && packet.dandelion_phase !== 'fluff') {
      this.drop(packet.id, peerId, 'phase-mismatch', 'PKT_FLUFF carried a non-fluff packet');
      return;
    }

    if (this.seen.has(packet.id) || this.hasStore(packet.id)) {
      this.drop(packet.id, peerId, 'duplicate', 'packet already seen');
      return;
    }
    this.markSeen(packet.id);

    if (kind === 'fluff') {
      this.acceptAndFanout(peerId, packet, 'fluff', packet.hop_count);
      return;
    }

    const hop = Math.min(packet.hop_count + 1, MAX_HOP_COUNT);
    const peers = this.transport.peerIds();
    const candidates = peers.filter((id) => id !== peerId);
    const overLimit = hop >= this.maxHops;
    const noPeers = candidates.length === 0;
    const probabilistic = !overLimit && !noPeers && this.random() < this.fluffProbability;

    if (overLimit || noPeers || probabilistic) {
      const reason = overLimit ? 'hop-limit' : noPeers ? 'no-peers' : 'probabilistic';
      const fluffed: SporePacket = {
        ...packet,
        hop_count: hop,
        dandelion_phase: 'fluff',
      };
      this.acceptAndFanout(peerId, fluffed, reason, hop);
      return;
    }

    const stemmed: SporePacket = {
      ...packet,
      hop_count: hop,
      dandelion_phase: 'stem',
    };
    const stored = this.store(stemmed);
    if (!stored.accepted || !stored.added) {
      this.drop(
        stemmed.id,
        peerId,
        stored.reason ?? 'rejected',
        stored.detail ?? 'stem packet was not stored',
      );
      return;
    }

    const target = pickOne(candidates, this.random);
    const messageOut: StemPacketMessage = {
      v: 1,
      t: 'PKT_STEM',
      packet: stemmed,
    };
    this.telemetry?.emit('pkt:stem', {
      id: stemmed.id,
      hop,
      peerId,
      target,
    });
    void this.send(target, encodeWireMessage(messageOut)).then((sent) => {
      if (!sent) {
        this.telemetry?.emit('pkt:drop', {
          id: stemmed.id,
          peerId: target,
          reason: 'send-failed',
        });
      }
    });
  }

  private acceptAndFanout(
    sourcePeer: string,
    packet: SporePacket,
    reason: string,
    hop: number,
  ): void {
    const stored = this.store(packet);
    if (!stored.accepted || !stored.added) {
      this.drop(
        packet.id,
        sourcePeer,
        stored.reason ?? 'rejected',
        stored.detail ?? 'fluff packet was not stored',
      );
      return;
    }

    this.fanout(sourcePeer, packet, reason, hop);
  }

  private fanout(sourcePeer: string, packet: SporePacket, reason: string, hop: number): void {
    const recipients = this.transport
      .peerIds()
      .filter((id) => id !== sourcePeer);
    const message: FluffPacketMessage = {
      v: 1,
      t: 'PKT_FLUFF',
      packet,
    };
    this.telemetry?.emit('pkt:fluff', {
      id: packet.id,
      hop,
      peerId: sourcePeer,
      reason,
      broadcast: recipients.length,
    });
    try {
      this.transport.broadcast(encodeWireMessage(message), [sourcePeer]);
    } catch (error) {
      this.drop(
        packet.id,
        sourcePeer,
        'broadcast-failed',
        error instanceof Error ? error.message : String(error),
      );
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

  private store(packet: SporePacket): DandelionAppendResult {
    const result = this.ingest(packet);
    if (result.accepted && result.added) this.onAccepted?.(packet);
    return result;
  }

  private markSeen(id: string): void {
    if (this.seen.has(id)) this.seen.delete(id);
    this.seen.set(id, true);
    while (this.seen.size > this.maxSeen) {
      const oldest = this.seen.keys().next().value;
      if (oldest === undefined) break;
      this.seen.delete(oldest);
    }
  }

  private drop(id: string, peerId: string, reason: string, detail?: string): void {
    this.telemetry?.emit('pkt:drop', {
      id,
      peerId,
      reason,
      ...(detail !== undefined ? { detail } : {}),
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
