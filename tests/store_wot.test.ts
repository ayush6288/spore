import { afterEach, describe, expect, it, vi } from 'vitest';
import { compressToBase64 } from 'lz-string';
import { generateIdentity, type SporeIdentity } from '../src/crypto/identity';
import { sealPacket, verifyPacket, type PacketKind, type SporePacket } from '../src/crypto/packet';
import { selectQuinePackets } from '../src/quine/compiler';
import {
  MAX_QUINE_STATE_CHARS,
  QUINE_CODEC,
  QUINE_STATE_ID,
  QUINE_STATE_VERSION,
  decodeQuineState,
  encodeQuineState,
  readQuineStateFromDocument,
} from '../src/quine/state';
import { LS_KEY, SporeStore } from '../src/storage/store';
import {
  DEFAULT_MIN_UNKNOWN_POW_BITS,
  DIRECT_SCORE,
  MUTED_SCORE,
  SECOND_HOP_SCORE,
  SELF_SCORE,
  TrustGraph,
  UNKNOWN_SCORE,
  encodeTrustContent,
  filterFeed,
  parseTrustCommand,
  type TrustRelation,
} from '../src/trust/wot';

const FIXED_TIME = 1_700_000_000;

interface SealOptions {
  readonly kind?: PacketKind;
  readonly powBits?: number;
  readonly createdAt?: number;
  readonly replyTo?: string;
}

async function seal(
  identity: SporeIdentity,
  content: string,
  options: SealOptions = {},
): Promise<SporePacket> {
  return sealPacket(
    {
      kind: options.kind ?? 'post',
      content,
      created_at: options.createdAt ?? FIXED_TIME,
      ...(options.replyTo !== undefined ? { reply_to: options.replyTo } : {}),
    },
    identity,
    { powBits: options.powBits ?? 0 },
  );
}

function memoryStorage(): Storage {
  const data = new Map<string, string>();
  return {
    get length() {
      return data.size;
    },
    clear() {
      data.clear();
    },
    getItem(key: string) {
      return data.get(key) ?? null;
    },
    key(index: number) {
      return [...data.keys()][index] ?? null;
    },
    removeItem(key: string) {
      data.delete(key);
    },
    setItem(key: string, value: string) {
      data.set(key, String(value));
    },
  };
}

function ids(packets: readonly SporePacket[]): string[] {
  return packets.map((packet) => packet.id);
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('SporeStore CRDT semantics', () => {
  it('deduplicates by packet id and merges idempotently', async () => {
    const author = generateIdentity();
    const a = await seal(author, 'alpha', { createdAt: FIXED_TIME + 1 });
    const b = await seal(author, 'beta', { createdAt: FIXED_TIME + 2 });
    const store = new SporeStore({ autoFlushMs: 0, seedJson: null });

    const first = store.merge([a, b, a]);
    expect(first).toMatchObject({ received: 3, added: 2, duplicates: 1, rejected: 0 });
    expect(store.size).toBe(2);
    expect(store.get(a.id)?.content).toBe('alpha');

    const second = store.merge([b, a, b, a]);
    expect(second).toMatchObject({ received: 4, added: 0, duplicates: 4 });
    expect(store.size).toBe(2);

    const snapshot = store.packetsSnapshot();
    expect(ids(snapshot)).toEqual([a.id, b.id]);
    expect(store.packetsSnapshot()).toEqual(snapshot);
  });

  it('rejects tampered packets at ingress without mutating the store', async () => {
    const author = generateIdentity();
    const packet = await seal(author, 'authentic');
    const store = new SporeStore({ autoFlushMs: 0, seedJson: null });

    const result = store.append({ ...packet, content: 'forged' });
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe('id-mismatch');
    expect(store.size).toBe(0);
    expect(result.evicted).toBe(0);
  });

  it('drops muted authors at ingress before they reach the store', async () => {
    const muted = generateIdentity();
    const keeper = generateIdentity();
    const mutedPacket = await seal(muted, 'should never land');
    const keeperPacket = await seal(keeper, 'should land');
    const store = new SporeStore({
      autoFlushMs: 0,
      seedJson: null,
      admit: (packet) => packet.pubkey !== muted.publicKey,
    });

    expect(store.append(mutedPacket)).toMatchObject({
      accepted: false,
      added: false,
      reason: 'muted',
    });
    expect(store.append(keeperPacket).accepted).toBe(true);
    expect(store.size).toBe(1);
    expect(store.get(mutedPacket.id)).toBeUndefined();

    const report = store.merge([mutedPacket, keeperPacket]);
    expect(report.muted).toBe(1);
    expect(report.duplicates).toBe(1);
    expect(store.size).toBe(1);
  });

  it('enforces an optional minimum PoW at ingress', async () => {
    const author = generateIdentity();
    const packet = await seal(author, 'light work', { powBits: 0 });
    // 32 bits keeps this deterministic: an unmined id would need a 1-in-2^32
    // accidental prefix to pass, unlike the old 8-bit threshold.
    const store = new SporeStore({ autoFlushMs: 0, seedJson: null, minPowBits: 32 });

    const result = store.append(packet);
    expect(result.accepted).toBe(false);
    expect(result.reason).toBe('below-minimum-pow');
    expect(store.size).toBe(0);
  });

  it('tracks reply edges and tips in the packet DAG', async () => {
    const author = generateIdentity();
    const parent = await seal(author, 'root post');
    const child = await seal(author, 'reply', { replyTo: parent.id });
    const sibling = await seal(author, 'another root');
    const store = new SporeStore({ autoFlushMs: 0, seedJson: null });

    store.merge([parent, child, sibling]);
    expect(ids(store.childrenOf(parent.id))).toEqual([child.id]);
    expect(ids(store.parentsOf(child))).toEqual([parent.id]);
    expect(store.parentsOf(parent)).toEqual([]);
    expect(ids(store.tips()).sort()).toEqual([child.id, sibling.id].sort());
  });

  it('evicts the lowest trust peer first and tombstones the id', async () => {
    const low = generateIdentity();
    const mid = generateIdentity();
    const high = generateIdentity();
    const scores = new Map<string, number>([
      [low.publicKey, 0.1],
      [mid.publicKey, 0.4],
      [high.publicKey, 0.8],
    ]);
    const lowPacket = await seal(low, 'low trust');
    const midPacket = await seal(mid, 'mid trust');
    const highPacket = await seal(high, 'high trust');

    const store = new SporeStore({
      maxPackets: 2,
      autoFlushMs: 0,
      seedJson: null,
      trustScore: (pubkey) => scores.get(pubkey) ?? 0.1,
    });

    store.append(lowPacket);
    store.append(midPacket);
    const result = store.append(highPacket);

    expect(result.accepted).toBe(true);
    expect(result.evicted).toBe(1);
    expect(store.size).toBe(2);
    expect(store.get(lowPacket.id)).toBeUndefined();
    expect(store.get(midPacket.id)).toBeDefined();
    expect(store.get(highPacket.id)).toBeDefined();

    const resurrect = store.append(lowPacket);
    expect(resurrect.accepted).toBe(false);
    expect(resurrect.reason).toBe('tombstoned');
    expect(store.size).toBe(2);
  });

  it('breaks trust ties by PoW, then timestamp, then id', async () => {
    const author = generateIdentity();
    const weak = await seal(author, 'weak', { powBits: 0, createdAt: FIXED_TIME });
    const strong = await seal(author, 'strong', { powBits: 1, createdAt: FIXED_TIME });
    const store = new SporeStore({ maxPackets: 1, autoFlushMs: 0, seedJson: null });

    store.append(weak);
    store.append(strong);
    expect(store.get(weak.id)).toBeUndefined();
    expect(store.get(strong.id)).toBeDefined();

    const older = await seal(author, 'older', { powBits: 0, createdAt: FIXED_TIME });
    const newer = await seal(author, 'newer', { powBits: 0, createdAt: FIXED_TIME + 60 });
    const chronological = new SporeStore({ maxPackets: 1, autoFlushMs: 0, seedJson: null });
    chronological.append(older);
    chronological.append(newer);
    expect(chronological.get(older.id)).toBeUndefined();
    expect(chronological.get(newer.id)).toBeDefined();
  });

  it('keeps the byte budget bounded under pressure', async () => {
    const author = generateIdentity();
    const store = new SporeStore({
      maxPackets: 100,
      maxBytes: 1_024,
      autoFlushMs: 0,
      seedJson: null,
    });

    const packets: SporePacket[] = [];
    for (let i = 0; i < 6; i += 1) {
      const packet = await seal(author, `padding-${i}-${'x'.repeat(240)}`);
      packets.push(packet);
      store.append(packet);
    }

    expect(store.bytes).toBeLessThanOrEqual(1_024);
    expect(store.size).toBeLessThan(packets.length);
    expect(store.size).toBeGreaterThan(0);
  });
});

describe('SporeStore persistence layers', () => {
  it('rehydrates from the embedded quine seed and marks seed packets', async () => {
    const author = generateIdentity();
    const a = await seal(author, 'seed one');
    const b = await seal(author, 'seed two');
    const seedJson = encodeQuineState([a, b], { createdAt: FIXED_TIME });

    const store = new SporeStore({ autoFlushMs: 0, seedJson });
    const report = await store.load();

    expect(report.seed).toBe(2);
    expect(report.rejected).toBe(0);
    expect(store.size).toBe(2);
    expect(store.isSeedPacket(a.id)).toBe(true);
    expect(store.isSeedPacket(b.id)).toBe(true);
    expect(store.packetsSnapshot().map((packet) => packet.content).sort()).toEqual([
      'seed one',
      'seed two',
    ]);
  });

  it('drops tampered seed packets but keeps the verified remainder', async () => {
    const author = generateIdentity();
    const good = await seal(author, 'genuine');
    const tampered: SporePacket = { ...good, content: 'swapped after signing' };
    const seedJson = encodeQuineState([tampered], { createdAt: FIXED_TIME });

    const store = new SporeStore({ autoFlushMs: 0, seedJson });
    const report = await store.load();

    expect(report.rejected).toBe(1);
    expect(report.seed).toBe(0);
    expect(store.size).toBe(0);
  });

  it('fails closed on a malformed seed envelope without crashing', async () => {
    const store = new SporeStore({ autoFlushMs: 0, seedJson: '{"v":99}' });
    const report = await store.load();

    expect(report.seed).toBe(0);
    expect(report.errors.length).toBe(1);
    expect(report.errors[0]).toMatch(/seed rejected/);
    expect(store.size).toBe(0);
  });

  it('honors tombstones loaded from persisted state before seeding', async () => {
    const author = generateIdentity();
    const packet = await seal(author, 'will be evicted');
    const storage = memoryStorage();
    storage.setItem(
      LS_KEY,
      JSON.stringify({
        v: 1,
        packets: [],
        evicted: [packet.id],
        updated_at: FIXED_TIME,
      }),
    );
    vi.stubGlobal('localStorage', storage);

    const store = new SporeStore({
      autoFlushMs: 0,
      seedJson: encodeQuineState([packet], { createdAt: FIXED_TIME }),
    });
    const report = await store.load();

    expect(report.tombstoned).toBe(1);
    expect(report.seed).toBe(0);
    expect(store.size).toBe(0);
  });

  it('falls back to localStorage and round-trips packets and tombstones', async () => {
    const authorA = generateIdentity();
    const authorB = generateIdentity();
    const low = await seal(authorA, 'evicted soon');
    const high = await seal(authorB, 'survives');
    const scores = new Map<string, number>([
      [authorA.publicKey, 0.1],
      [authorB.publicKey, 0.8],
    ]);
    const options = {
      maxPackets: 1,
      autoFlushMs: 0,
      seedJson: null,
      trustScore: (pubkey: string) => scores.get(pubkey) ?? 0.1,
    } as const;

    const storage = memoryStorage();
    vi.stubGlobal('localStorage', storage);

    const first = new SporeStore(options);
    first.append(low);
    first.append(high);
    await expect(first.flush()).resolves.toBe(true);
    expect(first.backendName).toBe('localstorage');

    const persisted = storage.getItem(LS_KEY);
    expect(persisted).not.toBeNull();
    const parsed = JSON.parse(persisted ?? '{}') as {
      packets?: SporePacket[];
      evicted?: string[];
    };
    expect(parsed.packets?.map((packet) => packet.id)).toEqual([high.id]);
    expect(parsed.evicted).toEqual([low.id]);

    const second = new SporeStore(options);
    const report = await second.load();
    expect(report.localstorage).toBe(1);
    expect(report.backend).toBe('localstorage');
    expect(second.get(high.id)?.content).toBe('survives');
    expect(second.append(low).reason).toBe('tombstoned');
  });

  it('degrades to memory when every persistence API throws', async () => {
    const author = generateIdentity();
    const packet = await seal(author, 'kept in ram');
    vi.stubGlobal('localStorage', {
      get length(): number {
        throw new Error('blocked');
      },
      clear() {
        throw new Error('blocked');
      },
      getItem() {
        throw new Error('blocked');
      },
      key() {
        throw new Error('blocked');
      },
      removeItem() {
        throw new Error('blocked');
      },
      setItem() {
        throw new Error('blocked');
      },
    } satisfies Storage);

    const store = new SporeStore({ autoFlushMs: 0, seedJson: null });
    store.append(packet);
    await expect(store.flush()).resolves.toBe(false);
    const report = await store.load();

    expect(store.backendName).toBe('memory');
    expect(store.size).toBe(1);
    expect(report.errors.length).toBeGreaterThan(0);
    expect(report.errors[0]).toMatch(/localStorage/);
  });
});

describe('Web-of-Trust scoring', () => {
  async function graphFixture(): Promise<{
    root: SporeIdentity;
    peer: SporeIdentity;
    second: SporeIdentity;
    stranger: SporeIdentity;
    follow: SporePacket;
    vouch: SporePacket;
    rootMute: SporePacket;
    peerMuteSecond: SporePacket;
    peerFollowsSecond: SporePacket;
  }> {
    const root = generateIdentity();
    const peer = generateIdentity();
    const second = generateIdentity();
    const stranger = generateIdentity();
    const follow = await seal(root, encodeTrustContent('follow', peer.publicKey), {
      kind: 'trust',
    });
    const vouch = await seal(peer, encodeTrustContent('vouch', second.publicKey), {
      kind: 'trust',
    });
    const rootMute = await seal(root, encodeTrustContent('mute', peer.publicKey), {
      kind: 'trust',
    });
    const peerMuteSecond = await seal(peer, encodeTrustContent('mute', second.publicKey), {
      kind: 'trust',
    });
    const peerFollowsSecond = await seal(
      peer,
      encodeTrustContent('follow', second.publicKey),
      { kind: 'trust' },
    );
    return {
      root,
      peer,
      second,
      stranger,
      follow,
      vouch,
      rootMute,
      peerMuteSecond,
      peerFollowsSecond,
    };
  }

  it('scores self, direct, second-hop, and unknown keys', async () => {
    const { root, peer, second, stranger, follow, vouch } = await graphFixture();
    const graph = new TrustGraph(root.publicKey, [follow, vouch]);

    expect(graph.score(root.publicKey)).toBe(SELF_SCORE);
    expect(graph.relation(root.publicKey)).toBe('self');
    expect(graph.score(peer.publicKey)).toBe(DIRECT_SCORE);
    expect(graph.relation(peer.publicKey)).toBe('direct');
    expect(graph.score(second.publicKey)).toBe(SECOND_HOP_SCORE);
    expect(graph.relation(second.publicKey)).toBe('second-hop');
    expect(graph.score(stranger.publicKey)).toBe(UNKNOWN_SCORE);
    expect(graph.relation(stranger.publicKey)).toBe('unknown');

    expect(graph.explain(second.publicKey)).toEqual({
      pubkey: second.publicKey,
      score: SECOND_HOP_SCORE,
      relation: 'second-hop',
      muted: false,
    });
  });

  it('requires an explicit vouch for second hop (peer follows do not count)', async () => {
    const { root, second, follow, peerFollowsSecond } = await graphFixture();
    const graph = new TrustGraph(root.publicKey, [follow, peerFollowsSecond]);
    expect(graph.score(second.publicKey)).toBe(UNKNOWN_SCORE);
  });

  it('makes root mutes absorbing and prevents muted peers from vouching', async () => {
    const { root, peer, second, follow, vouch, rootMute } = await graphFixture();
    const graph = new TrustGraph(root.publicKey, [vouch, follow, rootMute]);

    expect(graph.score(peer.publicKey)).toBe(MUTED_SCORE);
    expect(graph.relation(peer.publicKey)).toBe('muted');
    expect(graph.isMuted(peer.publicKey)).toBe(true);
    expect(graph.score(second.publicKey)).toBe(UNKNOWN_SCORE);
  });

  it('honors mutes published by direct peers when configured', async () => {
    const { root, second, follow, peerMuteSecond } = await graphFixture();
    const honored = new TrustGraph(root.publicKey, [follow, peerMuteSecond]);
    expect(honored.score(second.publicKey)).toBe(MUTED_SCORE);

    const ignored = new TrustGraph(root.publicKey, [follow, peerMuteSecond], {
      honorPeerMutes: false,
    });
    expect(ignored.score(second.publicKey)).toBe(UNKNOWN_SCORE);
  });

  it('applies the unknown-author PoW floor and drops muted authors at admission', async () => {
    const { root, peer, second, stranger, follow, vouch, rootMute } = await graphFixture();
    const graph = new TrustGraph(root.publicKey, [follow, vouch]);

    const base = await seal(stranger, 'stranger post', { powBits: 0 });
    const weak = { ...base, pow_bits: DEFAULT_MIN_UNKNOWN_POW_BITS - 1 };
    const strong = { ...base, pow_bits: DEFAULT_MIN_UNKNOWN_POW_BITS };
    expect(graph.admit(weak)).toBe(false);
    expect(graph.admit(strong)).toBe(true);

    const trusted = { ...base, pubkey: second.publicKey, pow_bits: 0 };
    expect(graph.admit(trusted)).toBe(true);

    const mutedGraph = new TrustGraph(root.publicKey, [follow, vouch, rootMute]);
    const muted = { ...base, pubkey: peer.publicKey, pow_bits: 64 };
    expect(mutedGraph.admit(muted)).toBe(false);
  });

  it('filters feeds by trust, excluding trust packets and muted authors', async () => {
    const { root, peer, second, stranger, follow, vouch } = await graphFixture();
    const mutedPeer = generateIdentity();
    const mutedFollow = await seal(root, encodeTrustContent('follow', mutedPeer.publicKey), {
      kind: 'trust',
    });
    const mutedMute = await seal(root, encodeTrustContent('mute', mutedPeer.publicKey), {
      kind: 'trust',
    });
    const graph = new TrustGraph(root.publicKey, [
      follow,
      vouch,
      mutedFollow,
      mutedMute,
    ]);

    const rootPost = await seal(root, 'root post');
    const peerPost = await seal(peer, 'peer post');
    const secondPost = { ...(await seal(second, 'second post')), pow_bits: 0 };
    const strangerPost = { ...(await seal(stranger, 'stranger post')), pow_bits: 16 };
    const strangerWeak = { ...(await seal(stranger, 'weak post')), pow_bits: 15 };
    const mutedPost = await seal(mutedPeer, 'muted post');

    const feed = filterFeed(
      [strangerWeak, secondPost, peerPost, mutedPost, rootPost, strangerPost, follow],
      graph,
    );
    expect(feed.map((packet) => packet.content)).toEqual([
      'root post',
      'peer post',
      'second post',
      'stranger post',
    ]);
    // The muted direct peer is dropped even though it is followed.
    expect(feed.some((packet) => packet.pubkey === mutedPeer.publicKey)).toBe(false);
  });

  it('is idempotent by packet id and ignores follows from non-root peers', async () => {
    const { root, second, follow, peerFollowsSecond } = await graphFixture();
    const graph = new TrustGraph(root.publicKey, [follow, peerFollowsSecond]);
    expect(graph.addPacket(follow)).toBe(false);
    expect(graph.addPackets([follow, peerFollowsSecond])).toBe(0);
    expect(graph.score(second.publicKey)).toBe(UNKNOWN_SCORE);
  });

  it('parses and validates trust commands', async () => {
    const root = generateIdentity();
    const peer = generateIdentity();
    const follow = await seal(root, encodeTrustContent('follow', peer.publicKey), {
      kind: 'trust',
    });
    expect(parseTrustCommand(follow)).toEqual({ action: 'follow', target: peer.publicKey });

    expect(parseTrustCommand({ ...follow, kind: 'post' })).toBeNull();
    expect(parseTrustCommand({ ...follow, content: 'follow:deadbeef' })).toBeNull();
    expect(parseTrustCommand({ ...follow, content: `follow:${peer.publicKey.toUpperCase()}` })).toBeNull();
    expect(
      parseTrustCommand({ ...follow, content: `follow:${root.publicKey}` }),
    ).toBeNull();

    expect(encodeTrustContent('mute', peer.publicKey)).toBe(`mute:${peer.publicKey}`);
    expect(() => encodeTrustContent('mute', 'abc')).toThrow(/pubkey/);
    expect(() => encodeTrustContent('like' as 'follow', peer.publicKey)).toThrow(/action/);
  });

  it('rejects invalid roots and thresholds', () => {
    expect(() => new TrustGraph('not-a-key')).toThrow(/hex pubkey/);
    expect(() => new TrustGraph('ab'.repeat(32), [], { minUnknownPowBits: -1 })).toThrow(
      /between 0 and 64/,
    );
  });

  it('reports direct, second-hop, muted, and unknown counts', async () => {
    const { root, follow, vouch, rootMute } = await graphFixture();
    const active = new TrustGraph(root.publicKey, [follow, vouch]);
    expect(active.stats()).toEqual({ direct: 1, secondHop: 1, muted: 0, unknown: 0 });

    const withMute = new TrustGraph(root.publicKey, [follow, vouch, rootMute]);
    expect(withMute.stats()).toEqual({ direct: 0, secondHop: 0, muted: 1, unknown: 0 });
    expect(DEFAULT_MIN_UNKNOWN_POW_BITS).toBe(16);
  });
});

describe('quine state codec', () => {
  it('round-trips verified packets deterministically', async () => {
    const author = generateIdentity();
    const a = await seal(author, 'one');
    const b = await seal(author, 'two');
    const c = await seal(author, 'three');

    const encoded = encodeQuineState([c, a, b], { createdAt: FIXED_TIME });
    const reordered = encodeQuineState([b, c, a], { createdAt: FIXED_TIME });
    expect(reordered).toBe(encoded);

    const decoded = decodeQuineState(encoded);
    expect(decoded.createdAt).toBe(FIXED_TIME);
    expect(decoded.rejected).toBe(0);
    expect(ids(decoded.packets)).toEqual([a.id, b.id, c.id].sort());
    expect(decoded.packets.every((packet) => verifyPacket(packet).ok)).toBe(true);
    expect(encoded).not.toContain('</script');
  });

  it('drops forged packets inside an otherwise valid envelope', async () => {
    const author = generateIdentity();
    const genuine = await seal(author, 'genuine');
    const forged: SporePacket = { ...genuine, content: 'forged after signing' };
    const payload = compressToBase64(JSON.stringify([genuine, forged]));
    const envelope = {
      v: QUINE_STATE_VERSION,
      codec: QUINE_CODEC,
      created_at: FIXED_TIME,
      count: 2,
      payload,
    };

    const decoded = decodeQuineState(JSON.stringify(envelope));
    expect(decoded.rejected).toBe(1);
    expect(ids(decoded.packets)).toEqual([genuine.id]);
  });

  it('fails closed on malformed envelopes and payloads', () => {
    const goodEnvelope = {
      v: QUINE_STATE_VERSION,
      codec: QUINE_CODEC,
      created_at: FIXED_TIME,
      count: 0,
      payload: compressToBase64('[]'),
    };

    expect(() => decodeQuineState('')).toThrow(/empty/);
    expect(() => decodeQuineState('{')).toThrow(/not valid JSON/);
    expect(() => decodeQuineState('[]')).toThrow(/must be an object/);
    expect(() => decodeQuineState(JSON.stringify({ ...goodEnvelope, v: 2 }))).toThrow(
      /version/,
    );
    expect(() => decodeQuineState(JSON.stringify({ ...goodEnvelope, codec: 'gzip' }))).toThrow(
      /codec/,
    );
    expect(() =>
      decodeQuineState(JSON.stringify({ ...goodEnvelope, extra: true })),
    ).toThrow(/Unknown quine state field/);
    expect(() =>
      decodeQuineState(JSON.stringify({ ...goodEnvelope, payload: 'not base64!' })),
    ).toThrow(/Base64/);
    expect(() =>
      decodeQuineState(JSON.stringify({ ...goodEnvelope, count: 1 })),
    ).toThrow(/count does not match/);
    expect(() =>
      decodeQuineState(
        JSON.stringify({
          ...goodEnvelope,
          payload: compressToBase64('{"not":"an array"}'),
        }),
      ),
    ).toThrow(/packet array/);
    expect(() => decodeQuineState('x'.repeat(MAX_QUINE_STATE_CHARS + 1))).toThrow(/16 MB/);
  });

  it('reads the seed from the document and tolerates broken DOM access', async () => {
    const author = generateIdentity();
    const packet = await seal(author, 'embedded');
    const state = encodeQuineState([packet], { createdAt: FIXED_TIME });

    const doc = {
      getElementById: (id: string) =>
        id === QUINE_STATE_ID ? ({ textContent: `  ${state}  ` } as unknown as Element) : null,
    } as unknown as Document;
    expect(readQuineStateFromDocument(doc)).toBe(state);

    const emptyDoc = {
      getElementById: () => ({ textContent: '   ' } as unknown as Element),
    } as unknown as Document;
    expect(readQuineStateFromDocument(emptyDoc)).toBeNull();

    const brokenDoc = {
      getElementById: () => {
        throw new Error('blocked');
      },
    } as unknown as Document;
    expect(readQuineStateFromDocument(brokenDoc)).toBeNull();
    expect(readQuineStateFromDocument(null)).toBeNull();

    vi.stubGlobal('document', {
      getElementById: () => ({ textContent: state } as unknown as Element),
    });
    expect(readQuineStateFromDocument()).toBe(state);
    // Explicit null disables the global document fallback.
    expect(readQuineStateFromDocument(null)).toBeNull();
  });
});

describe('quine packet selection', () => {
  it('keeps only verified packets, deduped and ordered by trust', async () => {
    const low = generateIdentity();
    const mid = generateIdentity();
    const high = generateIdentity();
    const lowPacket = await seal(low, 'low');
    const midPacket = await seal(mid, 'mid');
    const highPacket = await seal(high, 'high');
    const forged: SporePacket = { ...midPacket, content: 'forged' };
    const scores = new Map<string, number>([
      [low.publicKey, 0.1],
      [mid.publicKey, 0.4],
      [high.publicKey, 0.8],
    ]);

    const selected = selectQuinePackets(
      [lowPacket, forged, highPacket, midPacket, highPacket],
      {
        maxPackets: 2,
        trustScore: (pubkey) => scores.get(pubkey) ?? 0.1,
      },
    );

    expect(ids(selected)).toEqual([highPacket.id, midPacket.id]);
    expect(selected.every((packet) => verifyPacket(packet).ok)).toBe(true);
    expect(() => selectQuinePackets([], { maxPackets: 0 })).toThrow(/positive integer/);
  });

  it('orders equal-trust packets by declared work and recency', async () => {
    const author = generateIdentity();
    const weak = await seal(author, 'weak', { powBits: 0, createdAt: FIXED_TIME + 100 });
    const strong = await seal(author, 'strong', { powBits: 1, createdAt: FIXED_TIME });
    const older = await seal(author, 'older', { powBits: 0, createdAt: FIXED_TIME });
    const newer = await seal(author, 'newer', { powBits: 0, createdAt: FIXED_TIME + 1 });

    expect(ids(selectQuinePackets([weak, strong], { maxPackets: 1 }))).toEqual([strong.id]);
    expect(ids(selectQuinePackets([older, newer], { maxPackets: 1 }))).toEqual([newer.id]);
  });

  it('classifies relations used by the feed badges', async () => {
    const root = generateIdentity();
    const peer = generateIdentity();
    const follow = await seal(root, encodeTrustContent('follow', peer.publicKey), {
      kind: 'trust',
    });
    const graph = new TrustGraph(root.publicKey, [follow]);
    const relations: TrustRelation[] = [
      graph.relation(root.publicKey),
      graph.relation(peer.publicKey),
      graph.relation(generateIdentity().publicKey),
    ];
    expect(relations).toEqual(['self', 'direct', 'unknown']);
  });
});
