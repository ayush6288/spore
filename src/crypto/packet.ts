/**
 * SporePacket — the canonical SPORE wire object.
 *
 * Canonical serialization (mirrors Nostr's `[0, ...]` convention):
 *   [0, pubkey, created_at, kind, content, media_cid, reply_to, pow_nonce, pow_bits]
 *
 * `hop_count` and `dandelion_phase` are transport metadata and are deliberately
 * excluded from the signed id: relays may mutate them while a packet travels
 * the Dandelion stem, without invalidating the author's signature.
 *
 * The packet id is SHA-256 over the UTF-8 canonical JSON above. The Schnorr
 * signature is over the 32 raw id bytes, exactly like NIP-01 signs its event id.
 */

import { schnorr } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import type { SporeIdentity } from './identity';
import { assertHex, bytesToHex, hexToBytes, isHex, utf8ByteLength, utf8ToBytes } from './encoding';
import {
  MAX_NONCE,
  MAX_POW_BITS,
  countLeadingZeroBitsHex,
  mineHashcash,
  type MiningProgress,
} from './pow';

export const PACKET_VERSION = 0 as const;
export const PACKET_KINDS = ['post', 'receipt', 'trust'] as const;
export const DANDELION_PHASES = ['stem', 'fluff'] as const;

export type PacketKind = (typeof PACKET_KINDS)[number];
export type DandelionPhase = (typeof DANDELION_PHASES)[number];

export const DEFAULT_POW_BITS = 16;
export const MAX_CONTENT_BYTES = 64 * 1024;
export const MAX_REFERENCE_BYTES = 256;
export const MAX_HOP_COUNT = 255;
export const MAX_PACKET_JSON_CHARS = 3_000_000;

/** Video manifests are content-addressed by `media_id` (SHA-256 of the file). */
export const MAX_MEDIA_BYTES = 512 * 1024 * 1024;
export const MAX_MEDIA_CHUNKS = 8_192;
export const MAX_MEDIA_CHUNK_SIZE = 1024 * 1024;
export const MAX_INLINE_MEDIA_BYTES = 1_500_000;
export const MAX_INLINE_MEDIA_B64_CHARS = 2_100_000;
export const MAX_MEDIA_FILE_NAME_BYTES = 255;
export const MAX_MEDIA_MIME_BYTES = 128;
export const MAX_MEDIA_SOURCE_URL_BYTES = 2_048;

export interface MediaManifest {
  /** SHA-256 hex of the full video binary. */
  media_id: string;
  file_name: string;
  /** e.g. `video/mp4`, `video/webm`. */
  mime: string;
  /** Total byte length. */
  size: number;
  /** Default 65,536 (64 KiB). */
  chunk_size: number;
  total_chunks: number;
  /** SHA-256 hex of each chunk, in order. */
  chunk_hashes: string[];
  /** Original Instagram Reel / X / YouTube URL. */
  source_url?: string;
  /** Optional inline video bytes for small clips (<= 1.5 MB). */
  inline_data_b64?: string;
}

export interface SporePacket {
  /** 32-byte SHA-256 packet id, hex. */
  id: string;
  /** 32-byte x-only Schnorr public key, hex. */
  pubkey: string;
  /** Unix seconds. */
  created_at: number;
  kind: PacketKind;
  content: string;
  /** Content-addressed media reference (CID / blob hash). */
  media_cid?: string;
  /**
   * Optional chunked-media manifest. `media_cid` is the signed trust anchor:
   * every chunk and the assembled blob are verified against `media_id`, so a
   * relay cannot substitute bytes without failing the hash gates.
   */
  media_manifest?: MediaManifest;
  /** Parent packet id for replies. */
  reply_to?: string;
  pow_nonce: number;
  pow_bits: number;
  hop_count: number;
  dandelion_phase: DandelionPhase;
  /** 64-byte BIP340 Schnorr signature over the raw packet id, hex. */
  sig: string;
}

export interface CanonicalFieldSet {
  pubkey: string;
  created_at: number;
  kind: PacketKind;
  content: string;
  media_cid?: string;
  reply_to?: string;
  pow_nonce: number;
  pow_bits: number;
}

export type CanonicalPayload = readonly [
  0,
  string,
  number,
  PacketKind,
  string,
  string | null,
  string | null,
  number,
  number,
];

export interface PacketDraft {
  kind: PacketKind;
  content: string;
  created_at?: number;
  media_cid?: string;
  media_manifest?: MediaManifest;
  reply_to?: string;
  hop_count?: number;
  dandelion_phase?: DandelionPhase;
}

export interface SealPacketOptions {
  readonly powBits?: number;
  readonly nonceStart?: number;
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: MiningProgress) => void;
}

export interface VerifyPacketOptions {
  /** Reject packets whose declared work is below this threshold. */
  readonly minPowBits?: number;
  /** Override the 64 KiB content ceiling (useful for receipts). */
  readonly maxContentBytes?: number;
}

export type PacketFailureReason =
  | 'invalid-schema'
  | 'id-mismatch'
  | 'insufficient-pow'
  | 'below-minimum-pow'
  | 'invalid-signature';

export interface PacketVerificationOk {
  readonly ok: true;
  readonly packet: SporePacket;
  readonly leadingZeroBits: number;
}

export interface PacketVerificationFailure {
  readonly ok: false;
  readonly reason: PacketFailureReason;
  readonly detail: string;
}

export type PacketVerificationResult = PacketVerificationOk | PacketVerificationFailure;

export class InvalidPacketError extends Error {
  override readonly name = 'InvalidPacketError';

  constructor(
    readonly reason: PacketFailureReason,
    detail: string,
  ) {
    super(`${reason}: ${detail}`);
  }
}

const REQUIRED_KEYS = [
  'id',
  'pubkey',
  'created_at',
  'kind',
  'content',
  'pow_nonce',
  'pow_bits',
  'hop_count',
  'dandelion_phase',
  'sig',
] as const;

const PACKET_KEYS = new Set<string>([...REQUIRED_KEYS, 'media_cid', 'media_manifest', 'reply_to']);

const MANIFEST_KEYS = new Set<string>([
  'media_id',
  'file_name',
  'mime',
  'size',
  'chunk_size',
  'total_chunks',
  'chunk_hashes',
  'source_url',
  'inline_data_b64',
]);

const BASE64_RE = /^[A-Za-z0-9+/]*={0,2}$/;
const MIME_RE = /^[a-z0-9][a-z0-9!#$&^_.+-]*\/[a-z0-9][a-z0-9!#$&^_.+-]*$/i;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isLowerHex(value: unknown, byteLength: number): value is string {
  return isHex(value, byteLength) && value === value.toLowerCase();
}

function isSafeUint(value: unknown, max: number): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 && value <= max;
}

function isKind(value: unknown): value is PacketKind {
  return typeof value === 'string' && (PACKET_KINDS as readonly string[]).includes(value);
}

function isPhase(value: unknown): value is DandelionPhase {
  return typeof value === 'string' && (DANDELION_PHASES as readonly string[]).includes(value);
}

function fail(reason: PacketFailureReason, detail: string): PacketVerificationFailure {
  return { ok: false, reason, detail };
}

function validateReference(value: unknown, label: string): string | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'string' || value.length === 0) {
    throw new TypeError(`${label} must be a non-empty string when present`);
  }
  if (utf8ByteLength(value) > MAX_REFERENCE_BYTES) {
    throw new RangeError(`${label} exceeds ${MAX_REFERENCE_BYTES} UTF-8 bytes`);
  }
  return value;
}

/**
 * Strictly validate a media manifest. Throws on malformed input, mirroring the
 * draft validators; `verifyPacket` converts the throw into a schema failure.
 */
export function validateMediaManifest(value: unknown): MediaManifest {
  if (!isRecord(value)) throw new TypeError('media_manifest must be an object');
  for (const key of Object.keys(value)) {
    if (!MANIFEST_KEYS.has(key)) {
      throw new TypeError(`Unknown media_manifest field: ${key}`);
    }
  }

  const mediaId = value['media_id'];
  if (!isLowerHex(mediaId, 32)) {
    throw new TypeError('media_manifest.media_id must be 32 bytes of lowercase hex');
  }
  const fileName = value['file_name'];
  if (typeof fileName !== 'string' || fileName.length === 0) {
    throw new TypeError('media_manifest.file_name must be a non-empty string');
  }
  if (utf8ByteLength(fileName) > MAX_MEDIA_FILE_NAME_BYTES) {
    throw new RangeError(`media_manifest.file_name exceeds ${MAX_MEDIA_FILE_NAME_BYTES} UTF-8 bytes`);
  }
  if (/[\u0000-\u001f\u007f]/.test(fileName)) {
    throw new TypeError('media_manifest.file_name contains control characters');
  }
  const mime = value['mime'];
  if (typeof mime !== 'string' || !MIME_RE.test(mime)) {
    throw new TypeError('media_manifest.mime must be a valid media type');
  }
  if (utf8ByteLength(mime) > MAX_MEDIA_MIME_BYTES) {
    throw new RangeError(`media_manifest.mime exceeds ${MAX_MEDIA_MIME_BYTES} UTF-8 bytes`);
  }
  const size = value['size'];
  if (!isSafeUint(size, MAX_MEDIA_BYTES) || size < 1) {
    throw new RangeError(`media_manifest.size must be between 1 and ${MAX_MEDIA_BYTES}`);
  }
  const chunkSize = value['chunk_size'];
  if (!isSafeUint(chunkSize, MAX_MEDIA_CHUNK_SIZE) || chunkSize < 1) {
    throw new RangeError(
      `media_manifest.chunk_size must be between 1 and ${MAX_MEDIA_CHUNK_SIZE}`,
    );
  }
  const expectedChunks = Math.ceil(size / chunkSize);
  const totalChunks = value['total_chunks'];
  if (!isSafeUint(totalChunks, MAX_MEDIA_CHUNKS) || totalChunks < 1) {
    throw new RangeError(`media_manifest.total_chunks must be between 1 and ${MAX_MEDIA_CHUNKS}`);
  }
  if (totalChunks !== expectedChunks) {
    throw new RangeError('media_manifest.total_chunks does not match size / chunk_size');
  }

  const hashes = value['chunk_hashes'];
  if (!Array.isArray(hashes) || hashes.length !== totalChunks) {
    throw new TypeError('media_manifest.chunk_hashes must contain one hash per chunk');
  }
  for (const hash of hashes) {
    if (!isLowerHex(hash, 32)) {
      throw new TypeError('media_manifest.chunk_hashes entries must be 32 bytes of lowercase hex');
    }
  }

  const sourceUrl = value['source_url'];
  if (sourceUrl !== undefined) {
    if (typeof sourceUrl !== 'string' || sourceUrl.length === 0) {
      throw new TypeError('media_manifest.source_url must be a non-empty string when present');
    }
    if (utf8ByteLength(sourceUrl) > MAX_MEDIA_SOURCE_URL_BYTES) {
      throw new RangeError(
        `media_manifest.source_url exceeds ${MAX_MEDIA_SOURCE_URL_BYTES} UTF-8 bytes`,
      );
    }
  }

  const inline = value['inline_data_b64'];
  if (inline !== undefined) {
    if (typeof inline !== 'string' || inline.length === 0) {
      throw new TypeError('media_manifest.inline_data_b64 must be a non-empty string when present');
    }
    if (size > MAX_INLINE_MEDIA_BYTES) {
      throw new RangeError('inline media is only allowed for clips up to 1.5 MB');
    }
    if (inline.length > MAX_INLINE_MEDIA_B64_CHARS || !BASE64_RE.test(inline)) {
      throw new TypeError('media_manifest.inline_data_b64 is not valid bounded base64');
    }
    const padded = Math.ceil(size / 3) * 4;
    if (inline.length < padded - 2 || inline.length > padded) {
      throw new RangeError('media_manifest.inline_data_b64 length does not match size');
    }
  }

  return {
    media_id: mediaId,
    file_name: fileName,
    mime,
    size,
    chunk_size: chunkSize,
    total_chunks: totalChunks,
    chunk_hashes: hashes.slice() as string[],
    ...(sourceUrl !== undefined ? { source_url: sourceUrl } : {}),
    ...(inline !== undefined ? { inline_data_b64: inline } : {}),
  };
}

function validateContent(content: unknown, maxContentBytes: number): string {
  if (typeof content !== 'string') throw new TypeError('content must be a string');
  if (utf8ByteLength(content) > maxContentBytes) {
    throw new RangeError(`content exceeds ${maxContentBytes} UTF-8 bytes`);
  }
  return content;
}

function validateTimestamp(value: unknown): number {
  if (!isSafeUint(value, Number.MAX_SAFE_INTEGER)) {
    throw new TypeError('created_at must be a non-negative integer (Unix seconds)');
  }
  return value;
}

function validateDraft(draft: PacketDraft, maxContentBytes: number): {
  kind: PacketKind;
  content: string;
  created_at: number;
  media_cid?: string;
  media_manifest?: MediaManifest;
  reply_to?: string;
  hop_count: number;
  dandelion_phase: DandelionPhase;
} {
  if (!isRecord(draft)) throw new TypeError('Packet draft must be an object');
  if (!isKind(draft.kind)) throw new TypeError(`kind must be one of: ${PACKET_KINDS.join(', ')}`);
  const content = validateContent(draft.content, maxContentBytes);
  const created_at = draft.created_at === undefined ? Math.floor(Date.now() / 1000) : validateTimestamp(draft.created_at);
  const media_manifest =
    draft.media_manifest === undefined ? undefined : validateMediaManifest(draft.media_manifest);
  const media_cid = validateReference(draft.media_cid, 'media_cid');
  if (
    media_manifest !== undefined &&
    media_cid !== undefined &&
    media_cid !== media_manifest.media_id
  ) {
    throw new TypeError('media_cid must equal media_manifest.media_id when both are present');
  }
  // The signed media_cid is the trust anchor for the manifest.
  const boundMediaCid = media_manifest?.media_id ?? media_cid;
  const reply_to = validateReference(draft.reply_to, 'reply_to');
  const hop_count = draft.hop_count ?? 0;
  if (!isSafeUint(hop_count, MAX_HOP_COUNT)) {
    throw new RangeError(`hop_count must be an integer between 0 and ${MAX_HOP_COUNT}`);
  }
  const dandelion_phase = draft.dandelion_phase ?? 'stem';
  if (!isPhase(dandelion_phase)) {
    throw new TypeError(`dandelion_phase must be one of: ${DANDELION_PHASES.join(', ')}`);
  }
  return {
    kind: draft.kind,
    content,
    created_at,
    ...(boundMediaCid !== undefined ? { media_cid: boundMediaCid } : {}),
    ...(media_manifest !== undefined ? { media_manifest } : {}),
    ...(reply_to !== undefined ? { reply_to } : {}),
    hop_count,
    dandelion_phase,
  };
}

function validatePowBits(bits: number): number {
  if (!Number.isSafeInteger(bits) || bits < 0 || bits > MAX_POW_BITS) {
    throw new RangeError(`pow_bits must be an integer between 0 and ${MAX_POW_BITS}`);
  }
  return bits;
}

export function canonicalPayload(fields: CanonicalFieldSet): CanonicalPayload {
  return [
    PACKET_VERSION,
    fields.pubkey,
    fields.created_at,
    fields.kind,
    fields.content,
    fields.media_cid ?? null,
    fields.reply_to ?? null,
    fields.pow_nonce,
    fields.pow_bits,
  ];
}

export function canonicalJson(fields: CanonicalFieldSet): string {
  return JSON.stringify(canonicalPayload(fields));
}

export function canonicalBytes(fields: CanonicalFieldSet): Uint8Array {
  return utf8ToBytes(canonicalJson(fields));
}

/** SHA-256 over the canonical serialization, as lowercase hex. */
export function computePacketId(fields: CanonicalFieldSet): string {
  return bytesToHex(sha256(canonicalBytes(fields)));
}

/**
 * Build a JSON prefix ending right before the nonce so mining avoids
 * re-serializing the whole packet for every attempt. The produced bytes are
 * byte-identical to `canonicalBytes` with the candidate nonce filled in.
 */
function nonceSerializer(
  fields: Omit<CanonicalFieldSet, 'pow_nonce' | 'pow_bits'>,
  powBits: number,
): (nonce: number) => Uint8Array {
  const head = JSON.stringify([
    PACKET_VERSION,
    fields.pubkey,
    fields.created_at,
    fields.kind,
    fields.content,
    fields.media_cid ?? null,
    fields.reply_to ?? null,
  ]).slice(0, -1); // drop closing ']'
  return (nonce: number) => utf8ToBytes(`${head},${nonce},${powBits}]`);
}

export function signPacketId(id: string, identity: SporeIdentity): string {
  assertHex(id, 32, 'Packet id');
  const privateKey = assertHex(identity.privateKey, 32, 'Private key');
  return bytesToHex(schnorr.sign(hexToBytes(id), hexToBytes(privateKey)));
}

/**
 * Mine the PoW nonce, derive the id, and Schnorr-sign it.
 * Mining is cooperative: it yields to the event loop between slices.
 */
export async function sealPacket(
  draft: PacketDraft,
  identity: SporeIdentity,
  options: SealPacketOptions = {},
): Promise<SporePacket> {
  const fields = validateDraft(draft, MAX_CONTENT_BYTES);
  const powBits = validatePowBits(options.powBits ?? DEFAULT_POW_BITS);

  const derivedPubkey = bytesToHex(schnorr.getPublicKey(hexToBytes(identity.privateKey)));
  if (derivedPubkey !== identity.publicKey) {
    throw new Error('Identity public key does not match its private key');
  }

  const serialize = nonceSerializer(
    {
      pubkey: identity.publicKey,
      created_at: fields.created_at,
      kind: fields.kind,
      content: fields.content,
      ...(fields.media_cid !== undefined ? { media_cid: fields.media_cid } : {}),
      ...(fields.reply_to !== undefined ? { reply_to: fields.reply_to } : {}),
    },
    powBits,
  );

  const mined = await mineHashcash({
    bits: powBits,
    hash: (nonce) => sha256(serialize(nonce)),
    ...(options.nonceStart !== undefined ? { nonceStart: options.nonceStart } : {}),
    ...(options.signal !== undefined ? { signal: options.signal } : {}),
    ...(options.onProgress !== undefined ? { onProgress: options.onProgress } : {}),
  });

  const id = mined.id;
  const sig = signPacketId(id, identity);

  return Object.freeze({
    id,
    pubkey: identity.publicKey,
    created_at: fields.created_at,
    kind: fields.kind,
    content: fields.content,
    ...(fields.media_cid !== undefined ? { media_cid: fields.media_cid } : {}),
    ...(fields.media_manifest !== undefined ? { media_manifest: fields.media_manifest } : {}),
    ...(fields.reply_to !== undefined ? { reply_to: fields.reply_to } : {}),
    pow_nonce: mined.nonce,
    pow_bits: powBits,
    hop_count: fields.hop_count,
    dandelion_phase: fields.dandelion_phase,
    sig,
  });
}

/**
 * Strict verification. A packet is only accepted if every gate passes:
 * schema → id integrity → declared PoW → optional floor → Schnorr signature.
 */
export function verifyPacket(
  value: unknown,
  options: VerifyPacketOptions = {},
): PacketVerificationResult {
  const minPowBits = options.minPowBits ?? 0;
  if (!Number.isSafeInteger(minPowBits) || minPowBits < 0 || minPowBits > MAX_POW_BITS) {
    throw new RangeError('minPowBits must be an integer between 0 and 64');
  }
  const maxContentBytes = options.maxContentBytes ?? MAX_CONTENT_BYTES;
  if (!Number.isSafeInteger(maxContentBytes) || maxContentBytes < 0) {
    throw new RangeError('maxContentBytes must be a non-negative integer');
  }

  if (!isRecord(value)) return fail('invalid-schema', 'Packet must be an object');

  for (const key of Object.keys(value)) {
    if (!PACKET_KEYS.has(key)) return fail('invalid-schema', `Unknown packet field: ${key}`);
  }
  for (const key of REQUIRED_KEYS) {
    if (!(key in value)) return fail('invalid-schema', `Missing packet field: ${key}`);
  }

  const {
    id,
    pubkey,
    created_at,
    kind,
    content,
    media_cid,
    media_manifest,
    reply_to,
    pow_nonce,
    pow_bits,
    hop_count,
    dandelion_phase,
    sig,
  } = value;

  if (!isLowerHex(id, 32)) return fail('invalid-schema', 'id must be 32 bytes of lowercase hex');
  if (!isLowerHex(pubkey, 32)) return fail('invalid-schema', 'pubkey must be 32 bytes of lowercase hex');
  if (!isLowerHex(sig, 64)) return fail('invalid-schema', 'sig must be 64 bytes of lowercase hex');
  if (!isSafeUint(created_at, Number.MAX_SAFE_INTEGER)) {
    return fail('invalid-schema', 'created_at must be a non-negative integer');
  }
  if (!isKind(kind)) return fail('invalid-schema', `kind must be one of: ${PACKET_KINDS.join(', ')}`);
  if (typeof content !== 'string') return fail('invalid-schema', 'content must be a string');
  if (utf8ByteLength(content) > maxContentBytes) {
    return fail('invalid-schema', `content exceeds ${maxContentBytes} UTF-8 bytes`);
  }
  if (media_cid !== undefined && (typeof media_cid !== 'string' || media_cid.length === 0)) {
    return fail('invalid-schema', 'media_cid must be a non-empty string when present');
  }
  if (typeof media_cid === 'string' && utf8ByteLength(media_cid) > MAX_REFERENCE_BYTES) {
    return fail('invalid-schema', `media_cid exceeds ${MAX_REFERENCE_BYTES} UTF-8 bytes`);
  }
  if (reply_to !== undefined && (typeof reply_to !== 'string' || reply_to.length === 0)) {
    return fail('invalid-schema', 'reply_to must be a non-empty string when present');
  }
  if (typeof reply_to === 'string' && utf8ByteLength(reply_to) > MAX_REFERENCE_BYTES) {
    return fail('invalid-schema', `reply_to exceeds ${MAX_REFERENCE_BYTES} UTF-8 bytes`);
  }
  let manifest: MediaManifest | undefined;
  if (media_manifest !== undefined) {
    try {
      manifest = validateMediaManifest(media_manifest);
    } catch (error) {
      return fail(
        'invalid-schema',
        error instanceof Error ? error.message : 'media_manifest is malformed',
      );
    }
    if (media_cid === undefined) {
      return fail('invalid-schema', 'media_manifest requires a media_cid binding');
    }
    if (media_cid !== manifest.media_id) {
      return fail('invalid-schema', 'media_cid does not match media_manifest.media_id');
    }
  }
  if (!isSafeUint(pow_nonce, MAX_NONCE)) return fail('invalid-schema', 'pow_nonce must be a uint32');
  if (!isSafeUint(pow_bits, MAX_POW_BITS)) return fail('invalid-schema', 'pow_bits must be between 0 and 64');
  if (!isSafeUint(hop_count, MAX_HOP_COUNT)) return fail('invalid-schema', 'hop_count must be between 0 and 255');
  if (!isPhase(dandelion_phase)) {
    return fail('invalid-schema', `dandelion_phase must be one of: ${DANDELION_PHASES.join(', ')}`);
  }

  const packet: SporePacket = {
    id,
    pubkey,
    created_at,
    kind,
    content,
    ...(media_cid !== undefined ? { media_cid } : {}),
    ...(manifest !== undefined ? { media_manifest: manifest } : {}),
    ...(reply_to !== undefined ? { reply_to } : {}),
    pow_nonce,
    pow_bits,
    hop_count,
    dandelion_phase,
    sig,
  };

  const expectedId = computePacketId(packet);
  if (expectedId !== id) {
    return fail('id-mismatch', 'Packet id does not match its canonical serialization');
  }

  const leadingZeroBits = countLeadingZeroBitsHex(id);
  if (leadingZeroBits < pow_bits) {
    return fail(
      'insufficient-pow',
      `Packet declares ${pow_bits} bits but only has ${leadingZeroBits}`,
    );
  }
  if (leadingZeroBits < minPowBits) {
    return fail(
      'below-minimum-pow',
      `Packet has ${leadingZeroBits} bits, below the required ${minPowBits}`,
    );
  }

  let signatureValid = false;
  try {
    signatureValid = schnorr.verify(hexToBytes(sig), hexToBytes(id), hexToBytes(pubkey));
  } catch {
    signatureValid = false;
  }
  if (!signatureValid) return fail('invalid-signature', 'Schnorr signature does not verify');

  return { ok: true, packet, leadingZeroBits };
}

export function assertValidPacket(
  value: unknown,
  options: VerifyPacketOptions = {},
): SporePacket {
  const result = verifyPacket(value, options);
  if (!result.ok) throw new InvalidPacketError(result.reason, result.detail);
  return result.packet;
}

export function serializePacket(packet: SporePacket): string {
  assertValidPacket(packet);
  return JSON.stringify({
    id: packet.id,
    pubkey: packet.pubkey,
    created_at: packet.created_at,
    kind: packet.kind,
    content: packet.content,
    ...(packet.media_cid !== undefined ? { media_cid: packet.media_cid } : {}),
    ...(packet.media_manifest !== undefined
      ? { media_manifest: packet.media_manifest }
      : {}),
    ...(packet.reply_to !== undefined ? { reply_to: packet.reply_to } : {}),
    pow_nonce: packet.pow_nonce,
    pow_bits: packet.pow_bits,
    hop_count: packet.hop_count,
    dandelion_phase: packet.dandelion_phase,
    sig: packet.sig,
  });
}

export function parsePacket(json: string, options: VerifyPacketOptions = {}): PacketVerificationResult {
  if (typeof json !== 'string' || json.length === 0 || json.length > MAX_PACKET_JSON_CHARS) {
    return fail('invalid-schema', 'Packet JSON is empty or too large');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return fail('invalid-schema', 'Packet JSON is not valid JSON');
  }
  return verifyPacket(parsed, options);
}

export function parsePacketOrThrow(json: string, options: VerifyPacketOptions = {}): SporePacket {
  const result = parsePacket(json, options);
  if (!result.ok) throw new InvalidPacketError(result.reason, result.detail);
  return result.packet;
}
