import { describe, expect, it } from 'vitest';
import { generateIdentity } from '../src/crypto/identity';
import { sealPacket, verifyPacket } from '../src/crypto/packet';
import {
  HYDRA_RECEIPT_TYPE,
  buildHydraReceiptContent,
  createHydraReceipt,
  encodeReceiptContent,
  formatReceiptTimestamp,
  hashMediaBytes,
  hashMediaText,
  hashReceiptSource,
  normalizeSocialUrl,
  parseHydraReceipt,
  platformLabel,
  receiptProofText,
  verifyHydraReceipt,
} from '../src/receipts/hydraReceipt';

const FIXED_TIME = 1_700_000_000;
const HELLO_SHA256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';
const encoder = new TextEncoder();

describe('social URL normalization', () => {
  it('canonicalizes Instagram posts, reels and TV links', () => {
    for (const input of [
      'https://instagram.com/p/CxYz123_ab/',
      'instagram.com/reel/CxYz123_ab/?utm_source=ig_web',
      'https://www.instagram.com/tv/CxYz123_ab/',
      'https://m.instagram.com/p/CxYz123_ab',
    ]) {
      expect(normalizeSocialUrl(input)).toEqual({
        platform: 'instagram',
        url: 'https://www.instagram.com/p/CxYz123_ab/',
        postId: 'CxYz123_ab',
      });
    }
  });

  it('canonicalizes YouTube watch, shorts, live and short links', () => {
    const expected = {
      platform: 'youtube',
      url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      postId: 'dQw4w9WgXcQ',
    };
    for (const input of [
      'https://www.youtube.com/watch?v=dQw4w9WgXcQ&t=42s',
      'https://m.youtube.com/watch?v=dQw4w9WgXcQ',
      'youtube.com/shorts/dQw4w9WgXcQ',
      'https://youtu.be/dQw4w9WgXcQ?si=tracking',
      'https://www.youtube.com/live/dQw4w9WgXcQ',
    ]) {
      expect(normalizeSocialUrl(input)).toEqual(expected);
    }
  });

  it('canonicalizes X and legacy Twitter status links', () => {
    const expected = {
      platform: 'x',
      url: 'https://x.com/field_notes/status/1723456789012345678',
      postId: '1723456789012345678',
    };
    expect(normalizeSocialUrl('https://x.com/field_notes/status/1723456789012345678?s=20')).toEqual(
      expected,
    );
    expect(
      normalizeSocialUrl('https://twitter.com/field_notes/status/1723456789012345678'),
    ).toEqual(expected);
  });

  it('rejects profiles, channels, non-post pages and non-social hosts', () => {
    for (const input of [
      '',
      '   ',
      'https://instagram.com/field_notes',
      'https://youtube.com/@field_notes',
      'https://youtube.com/watch?v=',
      'https://x.com/field_notes',
      'https://example.com/p/CxYz123_ab/',
      'javascript:alert(1)',
      'not a url',
    ]) {
      expect(normalizeSocialUrl(input)).toBeNull();
    }
  });
});

describe('source hashing', () => {
  it('hashes text and bytes with SHA-256', () => {
    expect(hashMediaText('hello')).toBe(HELLO_SHA256);
    expect(hashMediaBytes(encoder.encode('hello'))).toBe(HELLO_SHA256);
    expect(hashReceiptSource({ kind: 'text', value: 'hello' })).toBe(HELLO_SHA256);
    expect(hashReceiptSource({ kind: 'media', value: encoder.encode('hello') })).toBe(
      HELLO_SHA256,
    );
  });

  it('refuses empty media and mismatched source kinds', () => {
    expect(() => hashReceiptSource({ kind: 'media', value: new Uint8Array() })).toThrow(/empty/);
    expect(() => hashReceiptSource({ kind: 'text', value: encoder.encode('x') })).toThrow(
      /must be a string/,
    );
    expect(() =>
      hashReceiptSource({ kind: 'media', value: 'text' as unknown as Uint8Array }),
    ).toThrow(/raw bytes/);
  });
});

describe('Hydra receipts', () => {
  it('creates, signs, parses and verifies a receipt', async () => {
    const identity = generateIdentity();
    const media = encoder.encode('original video bytes');
    const { packet, receipt } = await createHydraReceipt({
      identity,
      url: 'https://youtu.be/dQw4w9WgXcQ',
      source: { kind: 'media', value: media },
      note: 'archived before the takedown',
      createdAt: FIXED_TIME,
      powBits: 0,
    });

    expect(packet.kind).toBe('receipt');
    expect(packet.created_at).toBe(FIXED_TIME);
    expect(verifyPacket(packet).ok).toBe(true);
    expect(receipt).toMatchObject({
      v: 1,
      type: HYDRA_RECEIPT_TYPE,
      platform: 'youtube',
      url: 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
      post_id: 'dQw4w9WgXcQ',
      source_kind: 'media',
      source_sha256: hashMediaBytes(media),
      committed_at: FIXED_TIME,
      note: 'archived before the takedown',
    });
    expect(parseHydraReceipt(packet)).toEqual(receipt);

    const verification = verifyHydraReceipt(packet);
    expect(verification).toMatchObject({
      ok: true,
      checks: { signature: true, url: true, sourceHash: true, timestamp: true },
    });
    expect(verification.receipt).toEqual(receipt);
    expect(verification.packet?.id).toBe(packet.id);

    const proof = receiptProofText(packet);
    expect(proof).toContain('https://www.youtube.com/watch?v=dQw4w9WgXcQ');
    expect(proof).toContain(hashMediaBytes(media));
    expect(proof).toContain(packet.sig);
    expect(proof).toContain('archived before the takedown');
    expect(platformLabel('x')).toBe('X');
    expect(formatReceiptTimestamp(FIXED_TIME)).toBe('2023-11-14 22:13:20Z');
  });

  it('drops a receipt whose content was rewritten after signing', async () => {
    const identity = generateIdentity();
    const { packet } = await createHydraReceipt({
      identity,
      url: 'https://instagram.com/p/CxYz123_ab/',
      source: { kind: 'text', value: 'my original caption' },
      createdAt: FIXED_TIME,
      powBits: 0,
    });

    const parsed = JSON.parse(packet.content) as Record<string, unknown>;
    parsed['source_sha256'] = 'f'.repeat(64);
    const forged = { ...packet, content: JSON.stringify(parsed) };
    const verification = verifyHydraReceipt(forged);
    expect(verification.ok).toBe(false);
    expect(verification.checks.signature).toBe(false);
    expect(verification.reason).toMatch(/invalid-signature|id-mismatch/);
  });

  it('rejects a signed receipt whose committed_at does not match created_at', async () => {
    const identity = generateIdentity();
    const receipt = buildHydraReceiptContent({
      url: 'https://x.com/field_notes/status/1723456789012345678',
      source: { kind: 'text', value: 'timestamp binding' },
      committedAt: FIXED_TIME - 1,
    });
    const packet = await sealPacket(
      {
        kind: 'receipt',
        content: encodeReceiptContent(receipt),
        created_at: FIXED_TIME,
      },
      identity,
      { powBits: 0 },
    );

    const verification = verifyHydraReceipt(packet);
    expect(verification.ok).toBe(false);
    expect(verification.checks).toMatchObject({
      signature: true,
      url: true,
      sourceHash: true,
      timestamp: false,
    });
    expect(verification.reason).toMatch(/do not match/);
  });

  it('rejects malformed content and unknown receipt shapes', async () => {
    const identity = generateIdentity();
    const packet = await sealPacket(
      { kind: 'receipt', content: '{"v":1,"type":"wrong"}', created_at: FIXED_TIME },
      identity,
      { powBits: 0 },
    );
    expect(parseHydraReceipt(packet)).toBeNull();
    expect(verifyHydraReceipt(packet)).toMatchObject({
      ok: false,
      checks: { signature: true },
    });
    expect(() => receiptProofText(packet)).toThrow(/not a Hydra receipt/);

    const post = await sealPacket(
      { kind: 'post', content: 'not a receipt', created_at: FIXED_TIME },
      identity,
      { powBits: 0 },
    );
    expect(parseHydraReceipt(post)).toBeNull();
  });

  it('validates URLs, notes and timestamps when building content', () => {
    expect(() =>
      buildHydraReceiptContent({
        url: 'https://example.com/post/1',
        source: { kind: 'text', value: 'x' },
        committedAt: FIXED_TIME,
      }),
    ).toThrow(/Instagram, YouTube or X/);
    expect(() =>
      buildHydraReceiptContent({
        url: 'https://youtu.be/dQw4w9WgXcQ',
        source: { kind: 'text', value: 'x' },
        committedAt: FIXED_TIME,
        note: 'n'.repeat(281),
      }),
    ).toThrow(/280/);
    expect(() =>
      buildHydraReceiptContent({
        url: 'https://youtu.be/dQw4w9WgXcQ',
        source: { kind: 'text', value: 'x' },
        committedAt: -1,
      }),
    ).toThrow(/non-negative/);

    const content = buildHydraReceiptContent({
      url: 'https://youtu.be/dQw4w9WgXcQ',
      source: { kind: 'text', value: 'x' },
      committedAt: FIXED_TIME,
      note: '   ',
    });
    expect(content.note).toBeUndefined();
  });
});
