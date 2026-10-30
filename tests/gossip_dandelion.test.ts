import { describe, expect, it } from 'vitest';
import { generateIdentity, type SporeIdentity } from '../src/crypto/identity';
import { sealPacket, type SporePacket } from '../src/crypto/packet';
import { DandelionRouter, type DandelionAppendResult } from '../src/net/dandelion';
import {
  GossipEngine,
  diffInventories,
  type GossipAppendResult,
  type GossipStore,
} from '../src/net/gossip';
import {
  encodeWireMessage,
  parseWireMessage,
  type PacketMessage,
  type WireMessage,
} from '../src/net/protocol';
import { Telemetry } from '../src/net/telemetry';
import type { OutboundMesh } from '../src/net/transport';

const FIXED_TIME = 1_700_000_000;

class FakeMesh implements OutboundMesh {
  readonly peers = new Set<string>();
  readonly sent: Array<{ peerId: string; data: string }> = [];
  readonly broadcasts: Array<{ data: string; except: string[] }> = [];

  peerIds(): string[] {
    return [...this.peers];
  }

  async send(peerId: string, data: string): Promise<boolean> {
    this.sent.push({ peerId, data });
    return true;
  }

  broadcast(data: string, except: Iterable<string> = []): void {
    this.broadcasts.push({ data, except: [...except] });
  }
}

class MemoryStore implements GossipStore {
  readonly packets = new Map<string, SporePacket>();
  appendCalls = 0;

  packetsSnapshot(): SporePacket[] {
    return [...this.packets.values()];
  }

  get(id: string): SporePacket | undefined {
    return this.packets.get(id);
  }

  append(candidate: unknown): GossipAppendResult {
    this.appendCalls += 1;
    if (typeof candidate !== 'object' || candidate === null) {
      return { accepted: false, added: false, reason: 'invalid-schema' };
    }
    const packet = candidate as SporePacket;
    if (this.packets.has(packet.id)) {
      return { accepted: true, added: false, reason: 'duplicate' };
    }
    this.packets.set(packet.id, packet);
    return { accepted: true, added: true };
  }

  seed(packet: SporePacket): void {
    this.packets.set(packet.id, packet);
  }
}

function flush(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

async function makePacket(
  identity: SporeIdentity,
  content: string,
  createdAt: number = FIXED_TIME,
): Promise<SporePacket> {
  return sealPacket(
    { kind: 'post', content, created_at: createdAt },
    identity,
    { powBits: 0 },
  );
}

function decode(raw: string): WireMessage {
  const parsed = parseWireMessage(raw);
  if (!parsed.ok) throw new Error(parsed.reason);
  return parsed.message;
}

function messagesTo(mesh: FakeMesh, peerId: string): WireMessage[] {
  return mesh.sent
    .filter((entry) => entry.peerId === peerId)
    .map((entry) => decode(entry.data));
}

describe('anti-entropy inventory diffing', () => {
  it('returns only remote ids absent locally, in remote order and deduplicated', () => {
    const a = 'aa'.repeat(32);
    const b = 'bb'.repeat(32);
    const c = 'cc'.repeat(32);
    expect(diffInventories([a, b], [a, b, c, c])).toEqual([c]);
    expect(diffInventories([], [c, a, c, b])).toEqual([c, a, b]);
    expect(diffInventories([a], ['not-an-id', a])).toEqual([]);
  });

  it('sends an inventory on join, requests only missing ids, and completes after packets', async () => {
    const author = generateIdentity();
    const local = await makePacket(author, 'local', FIXED_TIME);
    const remoteB = await makePacket(author, 'remote-b', FIXED_TIME + 1);
    const remoteC = await makePacket(author, 'remote-c', FIXED_TIME + 2);
    const remoteD = await makePacket(author, 'remote-d', FIXED_TIME + 3);

    const store = new MemoryStore();
    store.seed(local);
    const mesh = new FakeMesh();
    mesh.peers.add('peer-b');
    const telemetry = new Telemetry({ now: () => FIXED_TIME });
    const gossip = new GossipEngine({
      transport: mesh,
      store,
      telemetry,
      autoSyncMs: null,
      randomSid: () => 'sid-join',
      now: () => FIXED_TIME,
    });

    gossip.onPeerJoin('peer-b');
    await flush();

    const initial = messagesTo(mesh, 'peer-b');
    expect(initial).toHaveLength(1);
    expect(initial[0]).toMatchObject({ v: 1, t: 'SYNC_INV', sid: 'sid-join', ids: [local.id] });

    // No blind flooding: nothing but the advertisement went out.
    expect(initial.some((message) => message.t === 'SYNC_PKT')).toBe(false);

    const inventory: WireMessage = {
      v: 1,
      t: 'SYNC_INV',
      sid: 'sid-remote',
      ids: [local.id, remoteB.id, remoteC.id, remoteD.id],
    };
    gossip.handleMessage('peer-b', inventory);
    await flush();

    const request = messagesTo(mesh, 'peer-b').at(-1);
    expect(request).toMatchObject({
      v: 1,
      t: 'SYNC_REQ',
      sid: 'sid-remote',
      ids: [remoteB.id, remoteC.id, remoteD.id],
    });

    gossip.handleMessage('peer-b', {
      v: 1,
      t: 'SYNC_PKT',
      sid: 'sid-remote',
      packets: [remoteB, remoteC, remoteD],
    });
    await flush();

    expect(store.packets.size).toBe(4);
    expect(store.packets.has(remoteB.id)).toBe(true);
    const complete = telemetry.snapshot().filter((event) => event.name === 'sync:complete');
    expect(complete).toHaveLength(1);
    expect(complete[0]?.data).toMatchObject({
      peerId: 'peer-b',
      sid: 'sid-remote',
      requested: 3,
      received: 3,
      added: 3,
      rejected: 0,
      ok: true,
    });
  });

  it('does not request anything when inventories already match', async () => {
    const author = generateIdentity();
    const local = await makePacket(author, 'already-synced');
    const store = new MemoryStore();
    store.seed(local);
    const mesh = new FakeMesh();
    mesh.peers.add('peer-b');
    const telemetry = new Telemetry();
    const gossip = new GossipEngine({
      transport: mesh,
      store,
      telemetry,
      autoSyncMs: null,
      randomSid: () => 'sid-match',
    });

    gossip.handleMessage('peer-b', {
      v: 1,
      t: 'SYNC_INV',
      sid: 'sid-match',
      ids: [local.id],
    });
    await flush();

    expect(messagesTo(mesh, 'peer-b')).toHaveLength(0);
    expect(telemetry.snapshot().map((event) => event.name)).toContain('sync:complete');
  });

  it('rejects tampered packets at the network boundary without touching storage', async () => {
    const author = generateIdentity();
    const valid = await makePacket(author, 'authentic');
    const tampered: SporePacket = { ...valid, content: 'tampered' };
    const store = new MemoryStore();
    const mesh = new FakeMesh();
    mesh.peers.add('peer-b');
    const telemetry = new Telemetry();
    const gossip = new GossipEngine({
      transport: mesh,
      store,
      telemetry,
      autoSyncMs: null,
      randomSid: () => 'sid-bad',
    });

    const raw = encodeWireMessage({
      v: 1,
      t: 'SYNC_PKT',
      sid: 'sid-bad',
      packets: [tampered],
    });
    const parsed = parseWireMessage(raw);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;

    gossip.handleMessage('peer-b', parsed.message);
    await flush();

    expect(store.appendCalls).toBe(0);
    expect(store.packets.size).toBe(0);
    const drop = telemetry.snapshot().find((event) => event.name === 'pkt:drop');
    expect(drop?.data).toMatchObject({ peerId: 'peer-b', reason: 'invalid-packet' });
  });

  it('batches requests above the response cap instead of overflowing one envelope', async () => {
    const author = generateIdentity();
    const store = new MemoryStore();
    const mesh = new FakeMesh();
    mesh.peers.add('peer-b');
    const telemetry = new Telemetry();
    const gossip = new GossipEngine({
      transport: mesh,
      store,
      telemetry,
      autoSyncMs: null,
      randomSid: () => 'sid-batch',
    });

    const remote: SporePacket[] = [];
    for (let index = 0; index < 30; index += 1) {
      remote.push(await makePacket(author, `batch-${index}`, FIXED_TIME + index));
    }

    gossip.handleMessage('peer-b', {
      v: 1,
      t: 'SYNC_INV',
      sid: 'sid-batch',
      ids: remote.map((packet) => packet.id),
    });
    await flush();

    const first = messagesTo(mesh, 'peer-b').at(-1);
    expect(first).toMatchObject({ t: 'SYNC_REQ', sid: 'sid-batch' });
    if (first?.t !== 'SYNC_REQ') throw new Error('expected first request');
    expect(first.ids).toHaveLength(24);

    const byId = new Map(remote.map((packet) => [packet.id, packet]));
    const firstPackets = first.ids.map((id) => byId.get(id));
    expect(firstPackets.every((packet) => packet !== undefined)).toBe(true);
    gossip.handleMessage('peer-b', {
      v: 1,
      t: 'SYNC_PKT',
      sid: 'sid-batch',
      packets: firstPackets,
    });
    await flush();

    const second = messagesTo(mesh, 'peer-b').at(-1);
    expect(second).toMatchObject({ t: 'SYNC_REQ', sid: 'sid-batch' });
    if (second?.t !== 'SYNC_REQ') throw new Error('expected second request');
    expect(second.ids).toHaveLength(6);
    expect(second.ids).toEqual(remote.slice(24).map((packet) => packet.id));

    gossip.handleMessage('peer-b', {
      v: 1,
      t: 'SYNC_PKT',
      sid: 'sid-batch',
      packets: second.ids.map((id) => byId.get(id)),
    });
    await flush();

    expect(store.packets.size).toBe(30);
    const complete = telemetry
      .snapshot()
      .filter((event) => event.name === 'sync:complete')
      .at(-1);
    expect(complete?.data).toMatchObject({
      sid: 'sid-batch',
      requested: 30,
      received: 30,
      added: 30,
      ok: true,
    });
  });

  it('prunes abandoned sync sessions after their TTL', async () => {
    const author = generateIdentity();
    const missing = await makePacket(author, 'never arrives');
    const store = new MemoryStore();
    const mesh = new FakeMesh();
    mesh.peers.add('peer-b');
    const telemetry = new Telemetry();
    let now = FIXED_TIME;
    const gossip = new GossipEngine({
      transport: mesh,
      store,
      telemetry,
      autoSyncMs: null,
      syncTtlMs: 5_000,
      now: () => now,
      randomSid: () => `sid-${now}`,
    });

    gossip.handleMessage('peer-b', {
      v: 1,
      t: 'SYNC_INV',
      sid: 'sid-stale',
      ids: [missing.id],
    });
    await flush();
    expect(messagesTo(mesh, 'peer-b').at(-1)).toMatchObject({ t: 'SYNC_REQ' });

    now += 6_000;
    gossip.syncWith('peer-b');
    await flush();

    const timeout = telemetry
      .snapshot()
      .find(
        (event) => event.name === 'sync:complete' && event.data['reason'] === 'timeout',
      );
    expect(timeout?.data).toMatchObject({ sid: 'sid-stale', ok: false, requested: 1 });
  });

  it('rejects malformed wire envelopes before routing', () => {
    expect(parseWireMessage('').ok).toBe(false);
    expect(parseWireMessage('{').ok).toBe(false);
    expect(
      parseWireMessage(JSON.stringify({ v: 1, t: 'SYNC_INV', sid: 'sid', ids: ['nope'] })).ok,
    ).toBe(false);
    expect(
      parseWireMessage(JSON.stringify({ v: 1, t: 'SYNC_REQ', sid: 'sid', ids: [], extra: true })).ok,
    ).toBe(false);
    expect(
      parseWireMessage(JSON.stringify({ v: 2, t: 'SYNC_INV', sid: 'sid', ids: [] })).ok,
    ).toBe(false);
  });
});

interface DandelionHarness {
  readonly router: DandelionRouter;
  readonly mesh: FakeMesh;
  readonly telemetry: Telemetry;
  readonly ingested: SporePacket[];
}

function makeDandelion(
  peers: string[],
  randomValues: number[],
  has: (id: string) => boolean = () => false,
): DandelionHarness {
  const mesh = new FakeMesh();
  for (const peer of peers) mesh.peers.add(peer);
  const telemetry = new Telemetry();
  const ingested: SporePacket[] = [];
  let cursor = 0;
  const router = new DandelionRouter({
    transport: mesh,
    telemetry,
    ingest: (packet): DandelionAppendResult => {
      ingested.push(packet);
      return { accepted: true, added: true };
    },
    has,
    random: () => {
      const value = randomValues[cursor];
      cursor += 1;
      return value ?? 0.99;
    },
  });
  return { router, mesh, telemetry, ingested };
}

function packetMessage(packet: SporePacket, phase: 'stem' | 'fluff'): PacketMessage {
  const raw = encodeWireMessage({
    v: 1,
    t: phase === 'stem' ? 'PKT_STEM' : 'PKT_FLUFF',
    packet,
  });
  const parsed = parseWireMessage(raw);
  if (!parsed.ok) throw new Error(parsed.reason);
  if (parsed.message.t !== 'PKT_STEM' && parsed.message.t !== 'PKT_FLUFF') {
    throw new Error('not a packet message');
  }
  return parsed.message;
}

describe('Dandelion++ routing', () => {
  it('sends a local publish to exactly one stem peer at hop 0', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'local publish');
    const { router, mesh, telemetry, ingested } = makeDandelion(
      ['peer-a', 'peer-b', 'peer-c'],
      [0.5],
    );

    const route = router.publish(packet);

    expect(route).toMatchObject({ accepted: true, added: true, phase: 'stem', target: 'peer-b' });
    expect(mesh.sent).toHaveLength(1);
    expect(mesh.sent[0]?.peerId).toBe('peer-b');
    const sent = decode(mesh.sent[0]?.data ?? '');
    expect(sent.t).toBe('PKT_STEM');
    if (sent.t !== 'PKT_STEM') return;
    expect(sent.packet).toMatchObject({ id: packet.id, hop_count: 0, dandelion_phase: 'stem' });
    expect(mesh.broadcasts).toHaveLength(0);
    expect(ingested).toHaveLength(1);
    expect(ingested[0]).toMatchObject({ hop_count: 0, dandelion_phase: 'stem' });
    expect(telemetry.snapshot()).toHaveLength(1);
    expect(telemetry.snapshot()[0]?.name).toBe('pkt:stem');
  });

  it('broadcasts directly when directFluff is requested', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'skip the stem');
    const { router, mesh, telemetry, ingested } = makeDandelion(
      ['peer-a', 'peer-b'],
      [0.5],
    );

    const route = router.publish(packet, { directFluff: true });

    expect(route).toMatchObject({ accepted: true, added: true, phase: 'fluff', target: null });
    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(1);
    expect(mesh.broadcasts[0]?.except).toEqual(['local']);
    expect(ingested).toHaveLength(1);
    expect(ingested[0]).toMatchObject({ hop_count: 0, dandelion_phase: 'fluff' });
    const broadcast = decode(mesh.broadcasts[0]?.data ?? '');
    expect(broadcast.t).toBe('PKT_FLUFF');
    const fluff = telemetry.snapshot().find((event) => event.name === 'pkt:fluff');
    expect(fluff?.data).toMatchObject({ reason: 'direct-fluff', hop: 0, broadcast: 2 });
  });

  it('fluffs immediately when no other peers exist', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'alone');
    const { router, mesh, telemetry, ingested } = makeDandelion(['peer-source'], [0.99]);

    router.handleMessage('peer-source', packetMessage(packet, 'stem'));

    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(1);
    expect(mesh.broadcasts[0]?.except).toEqual(['peer-source']);
    expect(ingested[0]).toMatchObject({ hop_count: 1, dandelion_phase: 'fluff' });
    const fluff = telemetry.snapshot().find((event) => event.name === 'pkt:fluff');
    expect(fluff?.data).toMatchObject({ reason: 'no-peers', hop: 1, peerId: 'peer-source' });
  });

  it('transitions to fluff with 30% per-hop probability and broadcasts to everyone else', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'probabilistic');
    const { router, mesh, telemetry, ingested } = makeDandelion(
      ['peer-source', 'peer-x', 'peer-y'],
      [0.1],
    );

    router.handleMessage('peer-source', packetMessage(packet, 'stem'));

    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(1);
    expect(mesh.broadcasts[0]?.except).toEqual(['peer-source']);
    expect(ingested[0]).toMatchObject({ hop_count: 1, dandelion_phase: 'fluff' });
    const fluff = telemetry.snapshot().find((event) => event.name === 'pkt:fluff');
    expect(fluff?.data).toMatchObject({ reason: 'probabilistic', hop: 1 });
  });

  it('always fluffs at hop_count >= 3 even when the random draw is high', async () => {
    const author = generateIdentity();
    const signed = await makePacket(author, 'three hops');
    const packet: SporePacket = { ...signed, hop_count: 2, dandelion_phase: 'stem' };
    const { router, mesh, telemetry, ingested } = makeDandelion(
      ['peer-source', 'peer-x', 'peer-y'],
      [0.99],
    );

    router.handleMessage('peer-source', packetMessage(packet, 'stem'));

    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(1);
    expect(ingested[0]).toMatchObject({ hop_count: 3, dandelion_phase: 'fluff' });
    const fluff = telemetry.snapshot().find((event) => event.name === 'pkt:fluff');
    expect(fluff?.data).toMatchObject({ reason: 'hop-limit', hop: 3 });
  });

  it('forwards a stem packet to exactly one other random peer and increments the hop', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'stem forward');
    const { router, mesh, telemetry, ingested } = makeDandelion(
      ['peer-source', 'peer-a', 'peer-b', 'peer-c'],
      [0.99, 0],
    );

    router.handleMessage('peer-source', packetMessage(packet, 'stem'));

    expect(mesh.broadcasts).toHaveLength(0);
    expect(mesh.sent).toHaveLength(1);
    expect(mesh.sent[0]?.peerId).toBe('peer-a');
    const forwarded = decode(mesh.sent[0]?.data ?? '');
    expect(forwarded.t).toBe('PKT_STEM');
    if (forwarded.t !== 'PKT_STEM') return;
    expect(forwarded.packet).toMatchObject({
      id: packet.id,
      hop_count: 1,
      dandelion_phase: 'stem',
    });
    expect(ingested[0]).toMatchObject({ hop_count: 1, dandelion_phase: 'stem' });
    const stem = telemetry.snapshot().find((event) => event.name === 'pkt:stem');
    expect(stem?.data).toMatchObject({ hop: 1, peerId: 'peer-source', target: 'peer-a' });
  });

  it('rebroadcasts a received fluff packet to all peers except its source', async () => {
    const author = generateIdentity();
    const signed = await makePacket(author, 'fluff relay');
    const packet: SporePacket = { ...signed, hop_count: 2, dandelion_phase: 'fluff' };
    const { router, mesh, telemetry, ingested } = makeDandelion(
      ['peer-source', 'peer-x', 'peer-y'],
      [0.99],
    );

    router.handleMessage('peer-source', packetMessage(packet, 'fluff'));

    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(1);
    expect(mesh.broadcasts[0]?.except).toEqual(['peer-source']);
    expect(ingested[0]).toMatchObject({ hop_count: 2, dandelion_phase: 'fluff' });
    const fluff = telemetry.snapshot().find((event) => event.name === 'pkt:fluff');
    expect(fluff?.data).toMatchObject({ hop: 2, peerId: 'peer-source' });
  });

  it('drops duplicates instead of forwarding them twice', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'no loops');
    const { router, mesh, telemetry } = makeDandelion(
      ['peer-source', 'peer-a', 'peer-b'],
      [0.99, 0, 0.99, 0],
    );
    const message = packetMessage(packet, 'stem');

    router.handleMessage('peer-source', message);
    router.handleMessage('peer-source', message);

    expect(mesh.sent).toHaveLength(1);
    expect(mesh.broadcasts).toHaveLength(0);
    const drop = telemetry.snapshot().find((event) => event.name === 'pkt:drop');
    expect(drop?.data).toMatchObject({ reason: 'duplicate' });
  });

  it('rejects tampered stem packets at the network boundary', async () => {
    const author = generateIdentity();
    const valid = await makePacket(author, 'authentic stem');
    const tampered: SporePacket = { ...valid, content: 'forged' };
    const { router, mesh, ingested, telemetry } = makeDandelion(
      ['peer-source', 'peer-a', 'peer-b'],
      [0.5],
    );

    router.handleMessage('peer-source', packetMessage(tampered, 'stem'));

    expect(ingested).toHaveLength(0);
    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(0);
    const drop = telemetry.snapshot().find((event) => event.name === 'pkt:drop');
    expect(drop?.data).toMatchObject({ peerId: 'peer-source', reason: 'invalid-packet' });
  });

  it('never fluffs a local publish telemetry event as stem when there are no peers', async () => {
    const author = generateIdentity();
    const packet = await makePacket(author, 'offline publish');
    const { router, mesh, telemetry, ingested } = makeDandelion([], [0.99]);

    const route = router.publish(packet);

    expect(route).toMatchObject({ accepted: true, phase: 'fluff', target: null });
    expect(mesh.sent).toHaveLength(0);
    expect(mesh.broadcasts).toHaveLength(0);
    expect(ingested[0]).toMatchObject({ hop_count: 0, dandelion_phase: 'stem' });
    expect(telemetry.snapshot().map((event) => event.name)).toEqual(['pkt:fluff']);
  });
});
