import { describe, expect, it } from 'vitest';
import {
  identityFromPrivateKey,
  type SporeIdentity,
} from '../src/crypto/identity';
import {
  MAX_INLINE_MEDIA_BYTES,
  parsePacket,
  sealPacket,
  serializePacket,
  verifyPacket,
  type MediaManifest,
} from '../src/crypto/packet';
import {
  DEFAULT_VIDEO_CHUNK_SIZE,
  VideoChunkCache,
  assembleVideoBlob,
  availableChunks,
  base64ToBytes,
  bytesToBase64,
  importInlineMedia,
  ingestVideoFile,
  sha256Hex,
  sliceVideoBytes,
  verifyAndStoreChunk,
} from '../src/media/videoSwarm';
import {
  encodeWireMessage,
  isMediaMessage,
  parseWireMessage,
  type MediaHaveMessage,
  type MediaReqMessage,
  type WireMessage,
} from '../src/net/protocol';
import { MediaSwarm } from '../src/net/swarm';
import type { OutboundMesh } from '../src/net/transport';

const PRIVATE_KEY = '00'.repeat(31) + '03';
const identity: SporeIdentity = identityFromPrivateKey(PRIVATE_KEY);

function emptyCache(): VideoChunkCache {
  return new VideoChunkCache({ indexedDB: null });
}

function sampleBytes(length: number, seed = 7): Uint8Array {
  const bytes = new Uint8Array(length);
  let state = seed >>> 0;
  for (let index = 0; index < length; index += 1) {
    state = (state * 1_664_525 + 1_013_904_223) >>> 0;
    bytes[index] = state >>> 24;
  }
  return bytes;
}

function smallSlice(length = 300, chunkSize = 64): ReturnType<typeof sliceVideoBytes> {
  return sliceVideoBytes(sampleBytes(length), {
    fileName: 'reel.mp4',
    mime: 'video/mp4',
    chunkSize,
    inlineSmallVideos: false,
  });
}

async function storeAll(
  slice: ReturnType<typeof sliceVideoBytes>,
  cache: VideoChunkCache,
): Promise<void> {
  for (let index = 0; index < slice.chunks.length; index += 1) {
    const chunk = slice.chunks[index];
    if (chunk === undefined) throw new Error(`missing chunk ${index}`);
    expect(await verifyAndStoreChunk(slice.manifest, index, chunk, cache)).toBe(true);
  }
}

describe('video slicing', () => {
  it('slices a clip into 64 KiB chunks and hashes each one', () => {
    const bytes = sampleBytes(DEFAULT_VIDEO_CHUNK_SIZE * 2 + 17);
    const slice = sliceVideoBytes(bytes, { fileName: 'reel.mp4', mime: 'video/mp4' });

    expect(slice.manifest.media_id).toBe(sha256Hex(bytes));
    expect(slice.manifest.chunk_size).toBe(DEFAULT_VIDEO_CHUNK_SIZE);
    expect(slice.manifest.total_chunks).toBe(3);
    expect(slice.manifest.size).toBe(bytes.length);
    expect(slice.chunks.map((chunk) => chunk.length)).toEqual([
      DEFAULT_VIDEO_CHUNK_SIZE,
      DEFAULT_VIDEO_CHUNK_SIZE,
      17,
    ]);
    expect(slice.manifest.chunk_hashes).toEqual(slice.chunks.map((chunk) => sha256Hex(chunk)));
  });

  it('inlines clips up to 1.5 MB but not larger files', () => {
    const small = smallSlice(300, 64);
    const inline = sliceVideoBytes(sampleBytes(300), {
      fileName: 'reel.mp4',
      mime: 'video/mp4',
      chunkSize: 64,
    });
    expect(inline.manifest.inline_data_b64).toBe(bytesToBase64(sampleBytes(300)));
    expect(small.manifest.inline_data_b64).toBeUndefined();
    expect(MAX_INLINE_MEDIA_BYTES).toBe(1_500_000);
  });

  it('rejects empty input, bad chunk sizes, and manifest/geometry mismatches', () => {
    const bytes = sampleBytes(128);
    expect(() => sliceVideoBytes(new Uint8Array(0), { fileName: 'a.mp4', mime: 'video/mp4' })).toThrow(
      RangeError,
    );
    expect(() =>
      sliceVideoBytes(bytes, { fileName: 'a.mp4', mime: 'video/mp4', chunkSize: 0 }),
    ).toThrow(RangeError);
    expect(() =>
      sliceVideoBytes(bytes, {
        fileName: 'a.mp4',
        mime: 'video/mp4',
        chunkSize: 1_048_577,
      }),
    ).toThrow(RangeError);
    expect(() => sliceVideoBytes(bytes, { fileName: ' ', mime: 'video/mp4' })).toThrow(TypeError);
    expect(() => sliceVideoBytes(bytes, { fileName: 'a.mp4', mime: '' })).toThrow(TypeError);
  });

  it('round-trips base64 for arbitrary byte strings', () => {
    for (const length of [0, 1, 2, 3, 4, 5, 64, 255]) {
      const bytes = sampleBytes(length);
      expect(base64ToBytes(bytesToBase64(bytes))).toEqual(bytes);
    }
    expect(() => base64ToBytes('not base64!')).toThrow(TypeError);
  });
});

describe('chunk verification and assembly', () => {
  it('stores only chunks whose hash and length match the manifest', async () => {
    const slice = smallSlice();
    const cache = emptyCache();
    expect(await verifyAndStoreChunk(slice.manifest, 0, slice.chunks[0]!, cache)).toBe(true);
    expect(await availableChunks(slice.manifest, cache)).toEqual([0]);

    const tampered = slice.chunks[1]!.slice();
    tampered[0] = tampered[0]! ^ 0xff;
    expect(await verifyAndStoreChunk(slice.manifest, 1, tampered, cache)).toBe(false);
    expect(await verifyAndStoreChunk(slice.manifest, 1, slice.chunks[1]!.slice(0, 3), cache)).toBe(
      false,
    );
    expect(await verifyAndStoreChunk(slice.manifest, slice.manifest.total_chunks, tampered, cache)).toBe(
      false,
    );
    expect(await verifyAndStoreChunk(slice.manifest, -1, tampered, cache)).toBe(false);
    expect(await availableChunks(slice.manifest, cache)).toEqual([0]);
  });

  it('assembles the exact original bytes and refuses to assemble incomplete media', async () => {
    const original = sampleBytes(300);
    const slice = smallSlice(original.length);
    const cache = emptyCache();

    expect(await assembleVideoBlob(slice.manifest, cache)).toBeNull();

    await storeAll(slice, cache);
    const blob = await assembleVideoBlob(slice.manifest, cache);
    expect(blob).not.toBeNull();
    expect(blob!.type).toBe('video/mp4');
    expect(new Uint8Array(await blob!.arrayBuffer())).toEqual(original);

    const other = emptyCache();
    for (let index = 0; index < slice.manifest.total_chunks - 1; index += 1) {
      await verifyAndStoreChunk(slice.manifest, index, slice.chunks[index]!, other);
    }
    expect(await assembleVideoBlob(slice.manifest, other)).toBeNull();
  });

  it('verifies and seeds an inline clip with zero peers', async () => {
    const original = sampleBytes(300);
    const slice = sliceVideoBytes(original, {
      fileName: 'tiny.webm',
      mime: 'video/webm',
      chunkSize: 64,
    });
    expect(slice.manifest.inline_data_b64).toBeDefined();

    const cache = emptyCache();
    expect(await importInlineMedia(slice.manifest, cache)).toBe(true);
    expect(await availableChunks(slice.manifest, cache)).toEqual([0, 1, 2, 3, 4]);
    const blob = await assembleVideoBlob(slice.manifest, cache);
    expect(new Uint8Array(await blob!.arrayBuffer())).toEqual(original);

    const forged: MediaManifest = {
      ...slice.manifest,
      inline_data_b64: bytesToBase64(sampleBytes(original.length, 99)),
    };
    expect(await importInlineMedia(forged, emptyCache())).toBe(false);
    const { inline_data_b64: _inline, ...withoutInline } = slice.manifest;
    expect(await importInlineMedia(withoutInline, emptyCache())).toBe(false);
  });

  it('ingests a File, caches every chunk, and reports its name and MIME', async () => {
    const original = sampleBytes(300);
    const file = new File([original.slice().buffer as ArrayBuffer], 'reel.mp4', {
      type: 'video/mp4',
    });
    const cache = emptyCache();
    const slice = await ingestVideoFile(file, undefined, { chunkSize: 64, cache });

    expect(slice.manifest.file_name).toBe('reel.mp4');
    expect(slice.manifest.mime).toBe('video/mp4');
    expect(slice.manifest.media_id).toBe(sha256Hex(original));
    expect(await availableChunks(slice.manifest, cache)).toHaveLength(slice.manifest.total_chunks);
  });
});

describe('media manifests in signed packets', () => {
  it('binds media_cid to the manifest and survives serialize/parse', async () => {
    const slice = smallSlice(300);
    const packet = await sealPacket(
      { kind: 'post', content: 'reel drop', media_manifest: slice.manifest },
      identity,
      { powBits: 0, nonceStart: 1 },
    );

    expect(packet.media_cid).toBe(slice.manifest.media_id);
    expect(packet.media_manifest?.chunk_hashes).toEqual(slice.manifest.chunk_hashes);
    expect(verifyPacket(packet).ok).toBe(true);

    const parsed = parsePacket(serializePacket(packet));
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) return;
    expect(parsed.packet.media_cid).toBe(slice.manifest.media_id);
    expect(parsed.packet.media_manifest).toEqual(slice.manifest);
  });

  it('rejects a mismatched media_cid or a manifest without a binding', async () => {
    const slice = smallSlice(300);
    await expect(
      sealPacket(
        {
          kind: 'post',
          content: 'bad binding',
          media_cid: '00'.repeat(32),
          media_manifest: slice.manifest,
        },
        identity,
        { powBits: 0 },
      ),
    ).rejects.toThrow(/media_cid must equal/);

    const packet = await sealPacket(
      { kind: 'post', content: 'reel drop', media_manifest: slice.manifest },
      identity,
      { powBits: 0, nonceStart: 1 },
    );
    const stripped = { ...packet, media_cid: undefined };
    expect(verifyPacket(stripped).ok).toBe(false);
    const swapped = { ...packet, media_cid: '00'.repeat(32) };
    expect(verifyPacket(swapped).ok).toBe(false);
  });
});

describe('media wire protocol', () => {
  const slice = smallSlice(300);
  const manifest = slice.manifest;

  it('parses MEDIA_HAVE, MEDIA_REQ, and MEDIA_CHUNK', () => {
    const have: MediaHaveMessage = {
      v: 1,
      t: 'MEDIA_HAVE',
      media_id: manifest.media_id,
      available_chunks: [2, 0, 1],
      manifest,
    };
    const parsedHave = parseWireMessage(encodeWireMessage(have));
    expect(parsedHave.ok).toBe(true);
    if (parsedHave.ok && isMediaMessage(parsedHave.message)) {
      expect(parsedHave.message.t).toBe('MEDIA_HAVE');
      if (parsedHave.message.t === 'MEDIA_HAVE') {
        expect(parsedHave.message.available_chunks).toEqual([0, 1, 2]);
        expect(parsedHave.message.manifest?.media_id).toBe(manifest.media_id);
      }
    }

    const request: MediaReqMessage = {
      v: 1,
      t: 'MEDIA_REQ',
      media_id: manifest.media_id,
      chunk_indices: [3, 1],
    };
    const parsedReq = parseWireMessage(encodeWireMessage(request));
    expect(parsedReq.ok).toBe(true);
    if (parsedReq.ok && parsedReq.message.t === 'MEDIA_REQ') {
      expect(parsedReq.message.chunk_indices).toEqual([1, 3]);
    }

    const chunk = {
      v: 1,
      t: 'MEDIA_CHUNK',
      media_id: manifest.media_id,
      chunk_index: 0,
      data_b64: bytesToBase64(slice.chunks[0]!),
    } as const;
    expect(parseWireMessage(encodeWireMessage(chunk)).ok).toBe(true);
  });

  it('rejects oversized request windows, bad base64, and unknown fields', () => {
    const base = {
      v: 1,
      t: 'MEDIA_REQ',
      media_id: manifest.media_id,
    };
    expect(
      parseWireMessage(JSON.stringify({ ...base, chunk_indices: [0, 1, 2, 3, 4, 5, 6] })).ok,
    ).toBe(false);
    expect(parseWireMessage(JSON.stringify({ ...base, chunk_indices: [] })).ok).toBe(false);
    expect(
      parseWireMessage(
        JSON.stringify({
          v: 1,
          t: 'MEDIA_CHUNK',
          media_id: manifest.media_id,
          chunk_index: 0,
          data_b64: '!!!!',
        }),
      ).ok,
    ).toBe(false);
    expect(
      parseWireMessage(
        JSON.stringify({
          v: 1,
          t: 'MEDIA_HAVE',
          media_id: manifest.media_id,
          available_chunks: [0],
          extra: true,
        }),
      ).ok,
    ).toBe(false);
    expect(
      parseWireMessage(
        JSON.stringify({
          v: 1,
          t: 'MEDIA_HAVE',
          media_id: manifest.media_id,
          available_chunks: [0],
          manifest: { ...manifest, media_id: '00'.repeat(32) },
        }),
      ).ok,
    ).toBe(false);
  });
});

/* --------------------------------------------------------------- fake mesh */

interface FakeNode extends OutboundMesh {
  readonly id: string;
  deliver?: (from: string, data: string) => void;
}

function fakeMesh(id: string, registry: Map<string, FakeNode>): FakeNode {
  const node: FakeNode = {
    id,
    peerIds: () => [...registry.keys()].filter((peerId) => peerId !== id),
    send: async (peerId, data) => {
      const target = registry.get(peerId);
      if (target?.deliver === undefined) return false;
      target.deliver(id, data);
      return true;
    },
    broadcast: (data, except) => {
      const skip = new Set(except ?? []);
      for (const peerId of node.peerIds()) {
        if (!skip.has(peerId)) void node.send(peerId, data);
      }
    },
  };
  return node;
}

describe('MediaSwarm exchange', () => {
  it('announces availability without inline bytes and deduplicates unchanged windows', async () => {
    const broadcasts: string[] = [];
    const mesh: OutboundMesh = {
      peerIds: () => ['peer-b'],
      send: async () => true,
      broadcast: (data) => broadcasts.push(data),
    };
    const cache = emptyCache();
    const slice = sliceVideoBytes(sampleBytes(300), {
      fileName: 'tiny.webm',
      mime: 'video/webm',
      chunkSize: 64,
    });
    expect(slice.manifest.inline_data_b64).toBeDefined();
    await storeAll(slice, cache);

    const swarm = new MediaSwarm({ transport: mesh, cache });
    try {
      await swarm.announce(slice.manifest);
      await swarm.announce(slice.manifest);
    } finally {
      swarm.stop();
    }

    expect(broadcasts).toHaveLength(1);
    const parsed = parseWireMessage(broadcasts[0]!);
    expect(parsed.ok).toBe(true);
    if (parsed.ok && parsed.message.t === 'MEDIA_HAVE') {
      expect(parsed.message.available_chunks).toEqual([0, 1, 2, 3, 4]);
      expect(parsed.message.manifest?.inline_data_b64).toBeUndefined();
      expect(parsed.message.manifest?.chunk_hashes).toEqual(slice.manifest.chunk_hashes);
    }
  });

  it('moves chunks between peers in bounded windows and verifies assembly', async () => {
    const registry = new Map<string, FakeNode>();
    const nodeA = fakeMesh('peer-a', registry);
    const nodeB = fakeMesh('peer-b', registry);
    registry.set('peer-a', nodeA);
    registry.set('peer-b', nodeB);

    const cacheA = emptyCache();
    const cacheB = emptyCache();
    const slice = smallSlice(384, 64);
    await storeAll(slice, cacheA);

    let resolveComplete: ((bytes: Uint8Array) => void) | null = null;
    const completed = new Promise<Uint8Array>((resolve) => {
      resolveComplete = resolve;
    });
    const errors: string[] = [];

    const swarmA = new MediaSwarm({ transport: nodeA, cache: cacheA, requestWindow: 4 });
    const swarmB = new MediaSwarm({
      transport: nodeB,
      cache: cacheB,
      requestWindow: 4,
      onError: (message) => errors.push(message),
      onComplete: (_manifest, blob) => {
        void blob.arrayBuffer().then((buffer) => resolveComplete?.(new Uint8Array(buffer)));
      },
    });

    const requests: number[] = [];
    nodeA.deliver = (_from, data) => {
      const parsed = parseWireMessage(data);
      if (!parsed.ok) return;
      if (parsed.message.t === 'MEDIA_REQ') requests.push(parsed.message.chunk_indices.length);
      if (isMediaMessage(parsed.message)) swarmA.handleMessage('peer-b', parsed.message);
    };
    nodeB.deliver = (_from, data) => {
      const parsed = parseWireMessage(data);
      if (parsed.ok && isMediaMessage(parsed.message)) swarmB.handleMessage('peer-a', parsed.message);
    };

    try {
      await swarmA.announce(slice.manifest);
      const bytes = await Promise.race([
        completed,
        new Promise<never>((_, reject) => {
          const timer = setTimeout(() => reject(new Error('media exchange timed out')), 4_000);
          (timer as unknown as { unref?: () => void }).unref?.();
        }),
      ]);
      expect(bytes).toEqual(sampleBytes(384));
      expect(await availableChunks(slice.manifest, cacheB)).toEqual([0, 1, 2, 3, 4, 5]);
      expect(requests.length).toBeGreaterThan(0);
      expect(Math.max(...requests)).toBe(4);
      expect(requests.every((count) => count <= 4)).toBe(true);
      expect(errors).toEqual([]);
      expect(swarmB.manifestCount).toBe(1);
    } finally {
      swarmA.stop();
      swarmB.stop();
    }
  });

  it('rejects request windows outside the protocol range', () => {
    const registry = new Map<string, FakeNode>();
    const node = fakeMesh('peer-a', registry);
    registry.set('peer-a', node);
    expect(() => new MediaSwarm({ transport: node, requestWindow: 0 })).toThrow(RangeError);
    expect(() => new MediaSwarm({ transport: node, requestWindow: 7 })).toThrow(RangeError);
  });

  it('drops chunks for unknown manifests without throwing', async () => {
    const registry = new Map<string, FakeNode>();
    const node = fakeMesh('peer-a', registry);
    registry.set('peer-a', node);
    const errors: string[] = [];
    const swarm = new MediaSwarm({
      transport: node,
      cache: emptyCache(),
      onError: (message) => errors.push(message),
    });
    const slice = smallSlice(64, 64);
    const message: WireMessage = {
      v: 1,
      t: 'MEDIA_CHUNK',
      media_id: slice.manifest.media_id,
      chunk_index: 0,
      data_b64: bytesToBase64(slice.chunks[0]!),
    };
    expect(isMediaMessage(message)).toBe(true);
    if (isMediaMessage(message)) swarm.handleMessage('peer-z', message);
    await Promise.resolve();
    expect(errors).toEqual(['received a chunk for an unknown manifest']);
    swarm.stop();
  });
});
