/**
 * Transport boundary shared by gossip and Dandelion.
 *
 * Both the Trystero mesh and the manual data channel implement this small
 * interface, so routing logic never depends on signaling details. Messages are
 * opaque strings at this layer; `protocol.ts` owns their schema.
 */

export type MeshTransportKind = 'nostr' | 'torrent' | 'manual';

export interface MeshPeerInfo {
  readonly id: string;
  readonly transports: readonly MeshTransportKind[];
  readonly rooms: readonly string[];
  readonly since: number;
}

export interface OutboundMesh {
  /** Currently connected peers, deduplicated across transports and rooms. */
  peerIds(): string[];
  /** Try to deliver one message to one peer. Resolves false when no route works. */
  send(peerId: string, data: string): Promise<boolean>;
  /** Fire-and-forget delivery to every peer except the excluded ids. */
  broadcast(data: string, except?: Iterable<string>): void;
}

export function transportLabel(kind: MeshTransportKind): string {
  switch (kind) {
    case 'nostr':
      return 'Nostr';
    case 'torrent':
      return 'BitTorrent';
    case 'manual':
      return 'direct SDP';
  }
}
