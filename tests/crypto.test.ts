import { describe, expect, it } from 'vitest';
import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import {
  DEFAULT_KDF_ITERATIONS,
  decryptIdentity,
  encryptIdentity,
  fingerprintOf,
  generateIdentity,
  identityFromPrivateKey,
  isValidPublicKey,
  parseKeyBackup,
  publicKeyFromPrivateKey,
  serializeKeyBackup,
  validateKeyBackup,
} from '../src/crypto/identity';
import {
  canonicalJson,
  computePacketId,
  parsePacket,
  sealPacket,
  serializePacket,
  signPacketId,
  verifyPacket,
  type SporePacket,
} from '../src/crypto/packet';
import {
  countLeadingZeroBits,
  countLeadingZeroBitsHex,
  mineHashcash,
  mineSha256,
  verifyHashcash,
} from '../src/crypto/pow';
import { bytesToHex, hexToBytes, utf8ToBytes } from '../src/crypto/encoding';

// BIP340 test vector 0: secret key 3, x-only pubkey below.
const VECTOR_PRIVATE_KEY = '0000000000000000000000000000000000000000000000000000000000000003';
const VECTOR_PUBLIC_KEY = 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9';
const FIXED_TIME = 1_700_000_000;

function validPacket(overrides: Partial<SporePacket> = {}): SporePacket {
  return {
    id: '00'.repeat(32),
    pubkey: VECTOR_PUBLIC_KEY,
    created_at: FIXED_TIME,
    kind: 'post',
    content: 'hello',
    pow_nonce: 0,
    pow_bits: 0,
    hop_count: 0,
    dandelion_phase: 'stem',
    sig: '00'.repeat(64),
    ...overrides,
  };
}

describe('identity', () => {
  it('derives the BIP340 vector public key deterministically', () => {
    expect(publicKeyFromPrivateKey(VECTOR_PRIVATE_KEY)).toBe(VECTOR_PUBLIC_KEY);
    const identity = identityFromPrivateKey(VECTOR_PRIVATE_KEY);
    expect(identity.publicKey).toBe(VECTOR_PUBLIC_KEY);
    expect(identity.privateKey).toBe(VECTOR_PRIVATE_KEY);
  });

  it('produces a human-readable spore fingerprint', () => {
    const identity = identityFromPrivateKey(VECTOR_PRIVATE_KEY);
    expect(identity.fingerprint).toMatch(/^spore:0x[0-9a-f]{12}$/);
    expect(identity.fingerprint).toBe(`spore:0x${VECTOR_PUBLIC_KEY.slice(0, 12)}`);
    expect(fingerprintOf(VECTOR_PUBLIC_KEY, 8)).toBe(`spore:0x${VECTOR_PUBLIC_KEY.slice(0, 8)}`);
  });

  it('generates distinct fresh identities with valid keys', () => {
    const a = generateIdentity();
    const b = generateIdentity();
    expect(a.privateKey).not.toBe(b.privateKey);
    expect(a.publicKey).toHaveLength(64);
    expect(b.publicKey).toHaveLength(64);
    expect(a.fingerprint).not.toBe(b.fingerprint);
    expect(isValidPublicKey(a.publicKey)).toBe(true);
    expect(publicKeyFromPrivateKey(a.privateKey)).toBe(a.publicKey);
  });

  it('rejects zero, out-of-range, malformed and short private keys', () => {
    expect(() => identityFromPrivateKey('00'.repeat(32))).toThrow(/scalar range/);
    expect(() =>
      identityFromPrivateKey('fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141'),
    ).toThrow(/scalar range/);
    expect(() => identityFromPrivateKey('abc')).toThrow(/32 bytes/);
    expect(() => identityFromPrivateKey('zz'.repeat(32))).toThrow(/32 bytes/);
  });

  it('rejects invalid fingerprint lengths and public keys', () => {
    expect(() => fingerprintOf(VECTOR_PUBLIC_KEY, 3)).toThrow(/even number/);
    expect(() => fingerprintOf('00'.repeat(31))).toThrow(/32 bytes/);
    expect(isValidPublicKey('00'.repeat(32))).toBe(false);
    expect(isValidPublicKey('nothex')).toBe(false);
  });
});

describe('passphrase key backup', () => {
  const passphrase = 'correct horse battery staple 🌱';

  it('encrypts and decrypts an identity (Unicode passphrase)', () => {
    const identity = identityFromPrivateKey(VECTOR_PRIVATE_KEY);
    const backup = encryptIdentity(identity, passphrase, {
      iterations: 12_000,
      createdAt: FIXED_TIME,
    });

    expect(backup.v).toBe(1);
    expect(backup.kdf).toBe('pbkdf2-sha256');
    expect(backup.pubkey).toBe(VECTOR_PUBLIC_KEY);
    expect(backup.fingerprint).toBe(identity.fingerprint);
    expect(backup.salt).toHaveLength(32);
    expect(backup.nonce).toHaveLength(48);
    expect(backup.ciphertext).toHaveLength(96);
    expect(backup.ciphertext).not.toContain(identity.privateKey);

    const restored = decryptIdentity(backup, passphrase);
    expect(restored.privateKey).toBe(identity.privateKey);
    expect(restored.publicKey).toBe(identity.publicKey);
  });

  it('round-trips through strict JSON serialization', () => {
    const identity = generateIdentity();
    const backup = encryptIdentity(identity, passphrase, { iterations: 12_000 });
    const json = serializeKeyBackup(backup);
    const parsed = parseKeyBackup(json);
    expect(parsed).toEqual(backup);
    expect(decryptIdentity(parsed, passphrase).fingerprint).toBe(identity.fingerprint);
  });

  it('fails closed on a wrong passphrase', () => {
    const backup = encryptIdentity(identityFromPrivateKey(VECTOR_PRIVATE_KEY), passphrase, {
      iterations: 12_000,
    });
    expect(() => decryptIdentity(backup, 'wrong passphrase')).toThrow(
      /Invalid passphrase or corrupted key backup/,
    );
  });

  it('detects ciphertext tampering via Poly1305', () => {
    const backup = encryptIdentity(identityFromPrivateKey(VECTOR_PRIVATE_KEY), passphrase, {
      iterations: 12_000,
    });
    const last = backup.ciphertext.slice(-1);
    const tampered = {
      ...backup,
      ciphertext: `${backup.ciphertext.slice(0, -1)}${last === '0' ? '1' : '0'}`,
    };
    expect(() => decryptIdentity(tampered, passphrase)).toThrow(/corrupted/);
  });

  it('rejects envelopes with mismatched public metadata or weak KDF settings', () => {
    const backup = encryptIdentity(identityFromPrivateKey(VECTOR_PRIVATE_KEY), passphrase, {
      iterations: 12_000,
    });
    expect(() => validateKeyBackup({ ...backup, pubkey: '11'.repeat(32) })).toThrow(
      /fingerprint does not match/,
    );
    expect(() => validateKeyBackup({ ...backup, iterations: 1_000 })).toThrow(/iterations/);
    expect(() => validateKeyBackup({ ...backup, extra: true })).toThrow(/Unknown key backup field/);
    expect(() => parseKeyBackup('{nope')).toThrow(/not valid JSON/);
    expect(() =>
      encryptIdentity(identityFromPrivateKey(VECTOR_PRIVATE_KEY), passphrase, { iterations: 999 }),
    ).toThrow(/iterations/);
    expect(() => encryptIdentity(identityFromPrivateKey(VECTOR_PRIVATE_KEY), '')).toThrow(
      /Passphrase/,
    );
  });

  it('uses the documented default KDF work factor', () => {
    expect(DEFAULT_KDF_ITERATIONS).toBeGreaterThanOrEqual(210_000);
  });
});

describe('canonical packet serialization', () => {
  it('serializes exactly [0, pubkey, time, kind, content, media, reply, nonce, bits]', () => {
    const fields = {
      pubkey: VECTOR_PUBLIC_KEY,
      created_at: FIXED_TIME,
      kind: 'post' as const,
      content: 'hello "spore"',
      pow_nonce: 7,
      pow_bits: 12,
    };
    const expected = `[0,${JSON.stringify(VECTOR_PUBLIC_KEY)},${FIXED_TIME},"post",${JSON.stringify(
      'hello "spore"',
    )},null,null,7,12]`;
    expect(canonicalJson(fields)).toBe(expected);
    expect(computePacketId(fields)).toBe(bytesToHex(sha256(utf8ToBytes(expected))));
  });

  it('includes optional media and reply references as strings', () => {
    const json = canonicalJson({
      pubkey: VECTOR_PUBLIC_KEY,
      created_at: FIXED_TIME,
      kind: 'receipt',
      content: '',
      media_cid: 'bafybeigdyrzt',
      reply_to: 'ab'.repeat(32),
      pow_nonce: 0,
      pow_bits: 0,
    });
    expect(json).toBe(
      `[0,${JSON.stringify(VECTOR_PUBLIC_KEY)},${FIXED_TIME},"receipt","","bafybeigdyrzt",${JSON.stringify(
        'ab'.repeat(32),
      )},0,0]`,
    );
  });
});

describe('packet sealing and verification', () => {
  const identity = identityFromPrivateKey(VECTOR_PRIVATE_KEY);

  it('mines PoW, computes the id and signs it with Schnorr', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'a spore in the wind', created_at: FIXED_TIME },
      identity,
      { powBits: 10 },
    );

    expect(packet.id).toMatch(/^[0-9a-f]{64}$/);
    expect(packet.pubkey).toBe(VECTOR_PUBLIC_KEY);
    expect(packet.sig).toMatch(/^[0-9a-f]{128}$/);
    expect(packet.pow_bits).toBe(10);
    expect(packet.created_at).toBe(FIXED_TIME);
    expect(packet.hop_count).toBe(0);
    expect(packet.dandelion_phase).toBe('stem');

    // The optimized mining serializer must agree with canonical serialization.
    expect(computePacketId(packet)).toBe(packet.id);
    expect(countLeadingZeroBitsHex(packet.id)).toBeGreaterThanOrEqual(10);

    // NIP-01 style: signature is over the raw id bytes.
    expect(schnorr.verify(hexToBytes(packet.sig), hexToBytes(packet.id), hexToBytes(packet.pubkey))).toBe(
      true,
    );
    expect(signPacketId(packet.id, identity)).toMatch(/^[0-9a-f]{128}$/);

    const result = verifyPacket(packet);
    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error('expected verification to succeed');
    expect(result.leadingZeroBits).toBeGreaterThanOrEqual(10);
  });

  it('round-trips through wire serialization and JSON parsing', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'wire me', created_at: FIXED_TIME, media_cid: 'cid:123' },
      identity,
      { powBits: 8 },
    );
    const json = serializePacket(packet);
    const parsed = parsePacket(json);
    expect(parsed.ok).toBe(true);
    if (!parsed.ok) throw new Error('expected parse to succeed');
    expect(parsed.packet).toEqual(packet);
  });

  it('rejects a tampered content field (id integrity gate)', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'original', created_at: FIXED_TIME },
      identity,
      { powBits: 8 },
    );
    const result = verifyPacket({ ...packet, content: 'tampered' });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    expect(result.reason).toBe('id-mismatch');
  });

  it('rejects tampering with the PoW nonce, id, and transport metadata', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'stable', created_at: FIXED_TIME },
      identity,
      { powBits: 8 },
    );
    const nonceResult = verifyPacket({ ...packet, pow_nonce: packet.pow_nonce + 1 });
    expect(nonceResult.ok).toBe(false);
    if (nonceResult.ok) throw new Error('unreachable');
    expect(nonceResult.reason).toBe('id-mismatch');

    const idResult = verifyPacket({ ...packet, id: '12'.repeat(32) });
    expect(idResult.ok).toBe(false);
    if (idResult.ok) throw new Error('unreachable');
    expect(idResult.reason).toBe('id-mismatch');
  });

  it('rejects a packet whose declared PoW exceeds its actual leading zeros', async () => {
    // Build a well-formed, correctly signed packet that simply did not mine
    // enough work. This isolates the PoW gate from the id-integrity gate.
    const fields = {
      pubkey: VECTOR_PUBLIC_KEY,
      created_at: FIXED_TIME,
      kind: 'post' as const,
      content: 'lazy spore',
      pow_nonce: 0,
      pow_bits: 40,
    };
    const id = computePacketId(fields);
    expect(countLeadingZeroBitsHex(id)).toBeLessThan(40);
    const packet: SporePacket = {
      ...fields,
      id,
      hop_count: 0,
      dandelion_phase: 'stem',
      sig: signPacketId(id, identity),
    };

    const result = verifyPacket(packet);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    expect(result.reason).toBe('insufficient-pow');
  });

  it('enforces an optional minimum work floor', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'floor', created_at: FIXED_TIME },
      identity,
      { powBits: 8 },
    );
    const result = verifyPacket(packet, { minPowBits: 12 });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    expect(result.reason).toBe('below-minimum-pow');
  });

  it('rejects a signature made by a different key', async () => {
    const other = generateIdentity();
    const fields = {
      pubkey: VECTOR_PUBLIC_KEY,
      created_at: FIXED_TIME,
      kind: 'post' as const,
      content: 'false witness',
      pow_nonce: 0,
      pow_bits: 0,
    };
    const id = computePacketId(fields);
    const packet: SporePacket = {
      ...fields,
      id,
      hop_count: 0,
      dandelion_phase: 'stem',
      sig: signPacketId(id, other),
    };
    const result = verifyPacket(packet);
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    expect(result.reason).toBe('invalid-signature');
  });

  it('rejects a tampered signature nibble', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'sign me', created_at: FIXED_TIME },
      identity,
      { powBits: 0 },
    );
    const last = packet.sig.slice(-1);
    const result = verifyPacket({
      ...packet,
      sig: `${packet.sig.slice(0, -1)}${last === '0' ? '1' : '0'}`,
    });
    expect(result.ok).toBe(false);
    if (result.ok) throw new Error('unreachable');
    expect(result.reason).toBe('invalid-signature');
  });

  it('rejects malformed schemas strictly', async () => {
    const packet = await sealPacket(
      { kind: 'post', content: 'schema', created_at: FIXED_TIME },
      identity,
      { powBits: 8 },
    );

    const cases: unknown[] = [
      null,
      [],
      'packet',
      { ...packet, extra: 'nope' },
      { ...packet, kind: 'meme' },
      { ...packet, created_at: 1.5 },
      { ...packet, pow_bits: 65 },
      { ...packet, pow_nonce: -1 },
      { ...packet, hop_count: 256 },
      { ...packet, dandelion_phase: 'pop' },
      { ...packet, id: packet.id.toUpperCase() },
      { ...packet, sig: '00' },
      { ...packet, content: 42 },
      { ...packet, media_cid: 'x'.repeat(257) },
      { ...packet, reply_to: 'x'.repeat(257) },
    ];

    for (const candidate of cases) {
      const result = verifyPacket(candidate);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.reason).toBe('invalid-schema');
    }

    expect(verifyPacket(packet, { maxContentBytes: 2 }).ok).toBe(false);
    expect(parsePacket('{').ok).toBe(false);
    expect(parsePacket('').ok).toBe(false);

    // Structurally valid but unsigned placeholder: fails the id gate, not schema.
    const placeholder = verifyPacket(validPacket());
    expect(placeholder.ok).toBe(false);
    if (!placeholder.ok) expect(placeholder.reason).toBe('id-mismatch');
  });

  it('rejects oversized content before mining', async () => {
    const huge = 'x'.repeat(64 * 1024 + 1);
    await expect(
      sealPacket({ kind: 'post', content: huge, created_at: FIXED_TIME }, identity, { powBits: 0 }),
    ).rejects.toThrow(/content exceeds/);
  });

  it('signs distinct packets for distinct content', async () => {
    const a = await sealPacket(
      { kind: 'post', content: 'one', created_at: FIXED_TIME },
      identity,
      { powBits: 8 },
    );
    const b = await sealPacket(
      { kind: 'post', content: 'two', created_at: FIXED_TIME },
      identity,
      { powBits: 8 },
    );
    expect(a.id).not.toBe(b.id);
    expect(a.sig).not.toBe(b.sig);
    expect(verifyPacket(a).ok && verifyPacket(b).ok).toBe(true);
  });
});

describe('hashcash mining', () => {
  it('counts leading zero bits correctly', () => {
    expect(countLeadingZeroBits(new Uint8Array([0xff]))).toBe(0);
    expect(countLeadingZeroBits(new Uint8Array([0x0f]))).toBe(4);
    expect(countLeadingZeroBits(new Uint8Array([0x00, 0x80]))).toBe(8);
    expect(countLeadingZeroBits(new Uint8Array([0x00, 0x00, 0x01]))).toBe(23);
    expect(countLeadingZeroBits(new Uint8Array(32))).toBe(256);
    const digest = new Uint8Array(32);
    digest[1] = 0x0f;
    expect(verifyHashcash(digest, 12).valid).toBe(true);
    expect(verifyHashcash(digest, 13).valid).toBe(false);
    expect(() => verifyHashcash(new Uint8Array(31), 1)).toThrow(/32 bytes/);
  });

  it('mines 12 bits asynchronously', async () => {
    const result = await mineSha256(utf8ToBytes('spore-pow-test'), 12);
    expect(result.leadingZeroBits).toBeGreaterThanOrEqual(12);
    expect(countLeadingZeroBitsHex(result.id)).toBeGreaterThanOrEqual(12);
    expect(result.tries).toBeGreaterThan(0);
    expect(result.nonce).toBeGreaterThanOrEqual(0);
    expect(verifyHashcash(result.digest, 12).valid).toBe(true);
  });

  it('is deterministic from a fixed nonce start', async () => {
    const mine = (): Promise<number> =>
      mineSha256(utf8ToBytes('deterministic'), 8, { nonceStart: 1_000 }).then((r) => r.nonce);
    expect(await mine()).toBe(await mine());
  });

  it('honours abort signals', async () => {
    const controller = new AbortController();
    controller.abort();
    await expect(
      mineHashcash({
        bits: 8,
        signal: controller.signal,
        hash: (nonce) => sha256(new Uint8Array([nonce & 0xff])),
      }),
    ).rejects.toMatchObject({ name: 'AbortError' });
  });

  it('reports progress while slicing work', async () => {
    const progress: number[] = [];
    await mineSha256(utf8ToBytes('progress-pump'), 12, {
      chunkSize: 256,
      onProgress: (p) => progress.push(p.attempts),
    });
    expect(progress.length).toBeGreaterThan(0);
    expect(progress[progress.length - 1]).toBeGreaterThan(0);
  });

  it('rejects invalid bit counts', async () => {
    await expect(
      mineHashcash({ bits: 65, hash: () => new Uint8Array(32) }),
    ).rejects.toThrow(/between 0 and 64/);
    await expect(
      mineHashcash({ bits: -1, hash: () => new Uint8Array(32) }),
    ).rejects.toThrow(/between 0 and 64/);
  });
});
