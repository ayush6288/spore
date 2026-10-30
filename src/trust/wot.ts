/**
 * SPORE Web-of-Trust (2 hops) and Sybil filtering.
 *
 * Trust commands are ordinary signed `kind: 'trust'` packets whose content is
 * exactly one of:
 *   follow:<64 lowercase hex pubkey>
 *   vouch:<64 lowercase hex pubkey>
 *   mute:<64 lowercase hex pubkey>
 *
 * Scoring:
 *   self                 1.0
 *   direct follow/vouch  0.8
 *   2-hop vouch          0.4   (only a *vouch* from a direct peer counts)
 *   unknown              0.1   (feed requires minUnknownPowBits, default 16)
 *   muted                0.0   (dropped at ingress/feed)
 *
 * Mutes are absorbing for the local root and for direct peers (when
 * `honorPeerMutes` is on). A muted direct peer cannot vouch anyone into the
 * 2-hop ring, which prevents a compromised follow from laundering trust.
 */

import { isHex } from '../crypto/encoding';
import type { SporePacket } from '../crypto/packet';

export const TRUST_ACTIONS = ['follow', 'vouch', 'mute'] as const;
export type TrustAction = (typeof TRUST_ACTIONS)[number];
export type TrustRelation = 'self' | 'direct' | 'second-hop' | 'unknown' | 'muted';

export const SELF_SCORE = 1;
export const DIRECT_SCORE = 0.8;
export const SECOND_HOP_SCORE = 0.4;
export const UNKNOWN_SCORE = 0.1;
export const MUTED_SCORE = 0;
export const DEFAULT_MIN_UNKNOWN_POW_BITS = 16;

const TRUST_CONTENT_RE = /^(follow|vouch|mute):([0-9a-f]{64})$/;

export interface TrustCommand {
  readonly action: TrustAction;
  readonly target: string;
}

export interface TrustOptions {
  /** PoW floor for packets authored by unknown keys to enter the feed. */
  readonly minUnknownPowBits?: number;
  /** Honour mutes published by direct (0.8) peers. Default true. */
  readonly honorPeerMutes?: boolean;
}

export interface TrustExplanation {
  readonly pubkey: string;
  readonly score: number;
  readonly relation: TrustRelation;
  readonly muted: boolean;
}

export interface FeedOptions {
  readonly minUnknownPowBits?: number;
}

export interface TrustStats {
  readonly direct: number;
  readonly secondHop: number;
  readonly muted: number;
  readonly unknown: number;
}

function addEdge(map: Map<string, Set<string>>, from: string, to: string): void {
  const existing = map.get(from);
  if (existing === undefined) {
    map.set(from, new Set([to]));
  } else {
    existing.add(to);
  }
}

export function encodeTrustContent(action: TrustAction, target: string): string {
  if (!(TRUST_ACTIONS as readonly string[]).includes(action)) {
    throw new TypeError(`Unknown trust action: ${String(action)}`);
  }
  if (!isHex(target, 32)) {
    throw new TypeError('Trust target must be a 32-byte lowercase hex pubkey');
  }
  return `${action}:${target.toLowerCase()}`;
}

/** Parse a trust packet, returning null for non-trust or malformed content. */
export function parseTrustCommand(packet: SporePacket): TrustCommand | null {
  if (packet.kind !== 'trust') return null;
  const match = TRUST_CONTENT_RE.exec(packet.content);
  if (match === null) return null;
  const action = match[1];
  const target = match[2];
  if (action === undefined || target === undefined) return null;
  if (!(TRUST_ACTIONS as readonly string[]).includes(action)) return null;
  if (target === packet.pubkey) return null;
  return { action: action as TrustAction, target };
}

export class TrustGraph {
  private readonly root: string;
  private readonly minUnknownPowBits: number;
  private readonly honorPeerMutes: boolean;
  private readonly direct = new Set<string>();
  private readonly selfMutes = new Set<string>();
  private readonly vouchesByAuthor = new Map<string, Set<string>>();
  private readonly mutesByAuthor = new Map<string, Set<string>>();
  private readonly processed = new Set<string>();

  private scoreCache: Map<string, number> | null = null;
  private relationCache: Map<string, TrustRelation> | null = null;

  constructor(root: string, packets: Iterable<SporePacket> = [], options: TrustOptions = {}) {
    if (!isHex(root, 32)) throw new TypeError('Trust root must be a 32-byte hex pubkey');
    this.root = root.toLowerCase();
    this.minUnknownPowBits = options.minUnknownPowBits ?? DEFAULT_MIN_UNKNOWN_POW_BITS;
    this.honorPeerMutes = options.honorPeerMutes ?? true;
    if (
      !Number.isSafeInteger(this.minUnknownPowBits) ||
      this.minUnknownPowBits < 0 ||
      this.minUnknownPowBits > 64
    ) {
      throw new RangeError('minUnknownPowBits must be between 0 and 64');
    }
    this.addPackets(packets);
  }

  get rootKey(): string {
    return this.root;
  }

  get unknownPowThreshold(): number {
    return this.minUnknownPowBits;
  }

  /** Returns true when the packet changed the graph. Idempotent by packet id. */
  addPacket(packet: SporePacket): boolean {
    const command = parseTrustCommand(packet);
    if (command === null) return false;
    if (this.processed.has(packet.id)) return false;
    this.processed.add(packet.id);

    if (packet.pubkey === this.root) {
      if (command.action === 'mute') {
        this.selfMutes.add(command.target);
      } else {
        this.direct.add(command.target);
      }
    } else if (command.action === 'mute') {
      addEdge(this.mutesByAuthor, packet.pubkey, command.target);
    } else if (command.action === 'vouch') {
      addEdge(this.vouchesByAuthor, packet.pubkey, command.target);
    }
    // Follows from non-root peers are deliberately ignored: two hops require
    // an explicit vouch, not a follow chain.

    this.invalidate();
    return true;
  }

  addPackets(packets: Iterable<SporePacket>): number {
    let changed = 0;
    for (const packet of packets) {
      if (this.addPacket(packet)) changed += 1;
    }
    return changed;
  }

  private invalidate(): void {
    this.scoreCache = null;
    this.relationCache = null;
  }

  private compute(): void {
    const scores = new Map<string, number>();
    const relations = new Map<string, TrustRelation>();
    scores.set(this.root, SELF_SCORE);
    relations.set(this.root, 'self');

    const tentativeDirect = new Set<string>();
    for (const peer of this.direct) {
      if (peer === this.root) continue;
      if (!this.selfMutes.has(peer)) tentativeDirect.add(peer);
    }

    const mutes = new Set<string>(this.selfMutes);
    if (this.honorPeerMutes) {
      for (const peer of tentativeDirect) {
        const peerMutes = this.mutesByAuthor.get(peer);
        if (peerMutes === undefined) continue;
        for (const target of peerMutes) {
          if (target !== this.root) mutes.add(target);
        }
      }
    }

    const activeDirect = new Set<string>();
    for (const peer of tentativeDirect) {
      if (mutes.has(peer)) {
        scores.set(peer, MUTED_SCORE);
        relations.set(peer, 'muted');
      } else {
        activeDirect.add(peer);
        scores.set(peer, DIRECT_SCORE);
        relations.set(peer, 'direct');
      }
    }

    for (const peer of activeDirect) {
      const vouches = this.vouchesByAuthor.get(peer);
      if (vouches === undefined) continue;
      for (const target of vouches) {
        if (target === this.root || activeDirect.has(target) || mutes.has(target)) continue;
        const existing = scores.get(target);
        if (existing === undefined || existing < SECOND_HOP_SCORE) {
          scores.set(target, SECOND_HOP_SCORE);
          relations.set(target, 'second-hop');
        }
      }
    }

    for (const muted of mutes) {
      if (muted === this.root) continue;
      scores.set(muted, MUTED_SCORE);
      relations.set(muted, 'muted');
    }

    this.scoreCache = scores;
    this.relationCache = relations;
  }

  score(pubkey: string): number {
    if (this.scoreCache === null) this.compute();
    return this.scoreCache?.get(pubkey.toLowerCase()) ?? UNKNOWN_SCORE;
  }

  relation(pubkey: string): TrustRelation {
    if (this.relationCache === null) this.compute();
    return this.relationCache?.get(pubkey.toLowerCase()) ?? 'unknown';
  }

  explain(pubkey: string): TrustExplanation {
    const normalized = pubkey.toLowerCase();
    const score = this.score(normalized);
    return {
      pubkey: normalized,
      score,
      relation: this.relation(normalized),
      muted: score === MUTED_SCORE,
    };
  }

  isMuted(pubkey: string): boolean {
    return this.score(pubkey) === MUTED_SCORE;
  }

  /** Sybil ingress check: muted dropped; unknown authors need the PoW floor. */
  admit(packet: SporePacket, options: FeedOptions = {}): boolean {
    const score = this.score(packet.pubkey);
    if (score <= MUTED_SCORE) return false;
    if (this.relation(packet.pubkey) === 'unknown') {
      const floor = options.minUnknownPowBits ?? this.minUnknownPowBits;
      return packet.pow_bits >= floor;
    }
    return true;
  }

  stats(): TrustStats {
    if (this.scoreCache === null) this.compute();
    let direct = 0;
    let secondHop = 0;
    let muted = 0;
    let unknown = 0;
    for (const relation of this.relationCache?.values() ?? []) {
      switch (relation) {
        case 'direct':
          direct += 1;
          break;
        case 'second-hop':
          secondHop += 1;
          break;
        case 'muted':
          muted += 1;
          break;
        case 'unknown':
          unknown += 1;
          break;
        case 'self':
          break;
      }
    }
    return { direct, secondHop, muted, unknown };
  }
}

/**
 * Main-feed policy: posts only, muted and sub-threshold strangers removed,
 * highest trust first, then newest, then id for a deterministic order.
 */
export function filterFeed(
  packets: Iterable<SporePacket>,
  graph: TrustGraph,
  options: FeedOptions = {},
): SporePacket[] {
  return [...packets]
    .filter((packet) => packet.kind === 'post' && graph.admit(packet, options))
    .sort((a, b) => {
      const scoreDelta = graph.score(b.pubkey) - graph.score(a.pubkey);
      if (scoreDelta !== 0) return scoreDelta;
      if (a.created_at !== b.created_at) return b.created_at - a.created_at;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    });
}
