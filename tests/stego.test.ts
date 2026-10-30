import { describe, expect, it } from 'vitest';
import { compressToUint8Array } from 'lz-string';
import { generateIdentity } from '../src/crypto/identity';
import { sealPacket, type SporePacket } from '../src/crypto/packet';
import {
  DEFAULT_STEGO_SIZE,
  STEGO_HEADER_BYTES,
  STEGO_MAGIC,
  buildStegoFrame,
  crc32,
  decodeStegoRgba,
  embedFrameInRgba,
  extractFrameFromRgba,
  frameCompressedPayload,
  rgbaCapacityBytes,
} from '../src/stego/pngCarrier';

const FIXED_TIME = 1_700_000_000;
const COVER_SIZE = 256;

function makeCover(alpha = (index: number): number => [0, 64, 128, 255][index % 4] ?? 255): Uint8ClampedArray {
  const pixels = COVER_SIZE * COVER_SIZE;
  const rgba = new Uint8ClampedArray(pixels * 4);
  for (let index = 0; index < pixels; index += 1) {
    rgba[index * 4] = (index * 7 + 11) & 0xff;
    rgba[index * 4 + 1] = (index * 13 + 29) & 0xff;
    rgba[index * 4 + 2] = (index * 31 + 53) & 0xff;
    rgba[index * 4 + 3] = alpha(index);
  }
  return rgba;
}

async function makePacket(content: string, createdAt = FIXED_TIME): Promise<SporePacket> {
  return sealPacket(
    { kind: 'post', content, created_at: createdAt },
    generateIdentity(),
    { powBits: 0 },
  );
}

describe('stego frame', () => {
  it('computes standard CRC-32 vectors', () => {
    expect(crc32(new Uint8Array())).toBe(0);
    expect(crc32(new TextEncoder().encode('123456789'))).toBe(0xcbf43926);
    expect(crc32(new TextEncoder().encode('SPOR'))).toBe(
      crc32(Uint8Array.from(STEGO_MAGIC)),
    );
  });

  it('sizes capacity from RGB bits only, skipping alpha', () => {
    const rgba = new Uint8ClampedArray(4 * 4);
    // 4 pixels × 3 channels = 12 bits → 1 whole byte.
    expect(rgbaCapacityBytes(rgba)).toBe(1);
    expect(() => rgbaCapacityBytes(new Uint8ClampedArray(5))).toThrow(/multiple of 4/);
  });

  it('rejects a frame larger than the cover buffer', () => {
    const cover = new Uint8ClampedArray(4 * 4);
    expect(() => embedFrameInRgba(cover, new Uint8Array(2))).toThrow(/needs 2 bytes/);
  });
});

describe('signed packet round-trip through raw RGBA', () => {
  it('embeds and decodes packets bit-exactly, preserving alpha', async () => {
    const first = await makePacket('the image is the carrier');
    const second = await makePacket('a second signed packet', FIXED_TIME + 60);
    const frame = buildStegoFrame([first, second], { createdAt: FIXED_TIME + 120 });
    expect(frame.length).toBeGreaterThan(STEGO_HEADER_BYTES);
    expect(Array.from(frame.slice(0, 4))).toEqual([0x53, 0x50, 0x4f, 0x52]);

    const cover = makeCover();
    const embedded = embedFrameInRgba(cover, frame);

    for (let index = 3; index < cover.length; index += 4) {
      expect(embedded[index]).toBe(cover[index]);
    }

    const extraction = extractFrameFromRgba(embedded);
    expect(extraction.crcValid).toBe(true);
    expect(extraction.reason).toBeUndefined();
    expect(extraction.compressed).not.toBeNull();
    expect(frame.slice(STEGO_HEADER_BYTES)).toEqual(extraction.compressed);

    const decoded = decodeStegoRgba(embedded);
    expect(decoded.crcValid).toBe(true);
    expect(decoded.rejected).toBe(0);
    expect(decoded.reason).toBeUndefined();
    expect(decoded.packets.map((packet) => packet.id)).toEqual([first.id, second.id]);
    expect(decoded.packets[0]).toEqual(first);
    expect(decoded.packets[1]).toEqual(second);
  });

  it('deduplicates repeated packets before embedding', async () => {
    const packet = await makePacket('only once');
    const frame = buildStegoFrame([packet, packet], { createdAt: FIXED_TIME });
    const embedded = embedFrameInRgba(makeCover(), frame);
    const decoded = decodeStegoRgba(embedded);
    expect(decoded.packets).toHaveLength(1);
  });

  it('refuses to embed an invalid or unsigned packet', async () => {
    const packet = await makePacket('honest');
    const tampered: SporePacket = { ...packet, content: 'forged' };
    expect(() => buildStegoFrame([tampered])).toThrow(/invalid packet/i);
    expect(() => buildStegoFrame([])).toThrow(/at least one packet/i);
  });
});

describe('stego corruption detection', () => {
  it('fails CRC32 when a payload LSB is flipped', async () => {
    const packet = await makePacket('fragile bits');
    const frame = buildStegoFrame([packet], { createdAt: FIXED_TIME });
    const embedded = embedFrameInRgba(makeCover(), frame);

    // Payload starts after the 12-byte header. Flip the LSB of its first byte.
    const bitIndex = STEGO_HEADER_BYTES * 8 + 7;
    const pixel = Math.floor(bitIndex / 3);
    const channel = bitIndex % 3;
    const offset = pixel * 4 + channel;
    embedded[offset] = (embedded[offset] ?? 0) ^ 1;

    const extraction = extractFrameFromRgba(embedded);
    expect(extraction.crcValid).toBe(false);
    expect(extraction.compressed).toBeNull();
    expect(extraction.reason).toMatch(/CRC32/);

    const decoded = decodeStegoRgba(embedded);
    expect(decoded.packets).toEqual([]);
    expect(decoded.crcValid).toBe(false);
  });

  it('rejects a buffer without the SPOR magic header', () => {
    const decoded = decodeStegoRgba(makeCover());
    expect(decoded.crcValid).toBe(false);
    expect(decoded.packets).toEqual([]);
    expect(decoded.reason).toMatch(/magic/);
  });

  it('reports a valid CRC but drops a tampered packet', async () => {
    const good = await makePacket('committed before takedown');
    const tampered: SporePacket = { ...good, content: 'rewritten after takedown' };
    const bundle = JSON.stringify({
      v: 1,
      created_at: FIXED_TIME,
      packets: [good, tampered],
    });
    const frame = frameCompressedPayload(compressToUint8Array(bundle));
    const embedded = embedFrameInRgba(makeCover(), frame);

    const decoded = decodeStegoRgba(embedded);
    expect(decoded.crcValid).toBe(true);
    expect(decoded.rejected).toBe(1);
    expect(decoded.reason).toMatch(/failed verification/);
    expect(decoded.packets.map((packet) => packet.id)).toEqual([good.id]);
  });

  it('reports a valid CRC but malformed bundle JSON', () => {
    const frame = frameCompressedPayload(compressToUint8Array('{"v":1,"packets":[]}'));
    const decoded = decodeStegoRgba(embedFrameInRgba(makeCover(), frame));
    expect(decoded.crcValid).toBe(true);
    expect(decoded.reason).toMatch(/malformed|unsupported/);
  });
});

describe('stego card constants', () => {
  it('keeps a 1080px default carrier', () => {
    expect(DEFAULT_STEGO_SIZE).toBe(1080);
  });
});
