/**
 * Hydra censorship receipts — commit before publish.
 *
 * A receipt is an ordinary signed `kind: 'receipt'` packet whose content
 * anchors an external post URL, the SHA-256 digest of the original media or
 * text, and the signed commit timestamp (`created_at`). Because the packet is
 * signed and PoW-bearing at commit time, it proves the author held that exact
 * source material *before* the external platform removed it — even if the
 * original URL now returns 404 or the account is gone.
 *
 * Content shape (stable, lowercase keys):
 *   {
 *     "v": 1,
 *     "type": "hydra-receipt",
 *     "platform": "instagram" | "youtube" | "x",
 *     "url": "https://…",              // canonicalized external anchor
 *     "post_id": "…",                  // platform post identifier
 *     "source_sha256": "<64 hex>",     // digest of the original bytes/text
 *     "source_kind": "media" | "text",
 *     "committed_at": <unix seconds>,  // must equal packet.created_at
 *     "note": "…"                      // optional, <= 280 chars
 *   }
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex, utf8ToBytes } from '../crypto/encoding';
import {
  sealPacket,
  verifyPacket,
  type PacketVerificationResult,
  type SporePacket,
} from '../crypto/packet';
import type { SporeIdentity } from '../crypto/identity';
import type { MiningProgress } from '../crypto/pow';

export const HYDRA_RECEIPT_VERSION = 1 as const;
export const HYDRA_RECEIPT_TYPE = 'hydra-receipt' as const;
export const MAX_RECEIPT_NOTE_CHARS = 280;
export const MAX_RECEIPT_SOURCE_BYTES = 64 * 1024 * 1024;

export const SOCIAL_PLATFORMS = ['instagram', 'youtube', 'x'] as const;
export type SocialPlatform = (typeof SOCIAL_PLATFORMS)[number];

export type ReceiptSourceKind = 'media' | 'text';

export interface HydraReceiptContent {
  readonly v: typeof HYDRA_RECEIPT_VERSION;
  readonly type: typeof HYDRA_RECEIPT_TYPE;
  readonly platform: SocialPlatform;
  readonly url: string;
  readonly post_id: string;
  readonly source_sha256: string;
  readonly source_kind: ReceiptSourceKind;
  readonly committed_at: number;
  readonly note?: string;
}

export interface NormalizedSocialUrl {
  readonly platform: SocialPlatform;
  readonly url: string;
  readonly postId: string;
}

export interface ReceiptSource {
  readonly kind: ReceiptSourceKind;
  /** Raw bytes for media, or UTF-8 text for a text post. */
  readonly value: Uint8Array | string;
}

export interface CreateHydraReceiptOptions {
  readonly identity: SporeIdentity;
  /** External post URL on Instagram, YouTube or X/Twitter. */
  readonly url: string;
  /** The original media bytes or text that was published externally. */
  readonly source: ReceiptSource;
  /** Optional human note; max 280 characters. */
  readonly note?: string;
  readonly powBits?: number;
  readonly createdAt?: number;
  readonly signal?: AbortSignal;
  readonly onProgress?: (progress: MiningProgress) => void;
}

export interface ReceiptChecks {
  readonly signature: boolean;
  readonly url: boolean;
  readonly sourceHash: boolean;
  readonly timestamp: boolean;
}

export interface ReceiptVerification {
  readonly ok: boolean;
  readonly packet: SporePacket | null;
  readonly receipt: HydraReceiptContent | null;
  readonly checks: ReceiptChecks;
  readonly reason?: string;
}

const PLATFORM_LABELS: Record<SocialPlatform, string> = {
  instagram: 'Instagram',
  youtube: 'YouTube',
  x: 'X',
};

const RECEIPT_KEYS = new Set([
  'v',
  'type',
  'platform',
  'url',
  'post_id',
  'source_sha256',
  'source_kind',
  'committed_at',
  'note',
]);

const SOURCE_HASH_RE = /^[0-9a-f]{64}$/;
const INSTAGRAM_PATH_RE = /^\/(?:p|reel|reels|tv)\/([A-Za-z0-9_-]{5,64})(?:\/|$)/;
const YOUTUBE_ID_RE = /^[A-Za-z0-9_-]{6,32}$/;
const X_STATUS_RE = /^\/([A-Za-z0-9_]{1,30})\/status(?:es)?\/(\d{1,32})(?:\/|$)/;

export function isSocialPlatform(value: unknown): value is SocialPlatform {
  return typeof value === 'string' && (SOCIAL_PLATFORMS as readonly string[]).includes(value);
}

export function platformLabel(platform: SocialPlatform): string {
  return PLATFORM_LABELS[platform];
}

function stripHostPrefix(hostname: string): string {
  return hostname.toLowerCase().replace(/^(?:www\.|m\.|mobile\.)/, '');
}

/**
 * Validate and canonicalize an Instagram, YouTube or X/Twitter post URL.
 * Returns null when the URL is not a recognizable single post.
 */
export function normalizeSocialUrl(input: string): NormalizedSocialUrl | null {
  if (typeof input !== 'string' || input.trim().length === 0) return null;
  const raw = input.trim();
  if (raw.length > 2_048) return null;

  let parsed: URL;
  try {
    parsed = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`);
  } catch {
    return null;
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return null;

  const host = stripHostPrefix(parsed.hostname);
  const path = parsed.pathname;

  if (host === 'instagram.com' || host === 'instagr.am') {
    const match = INSTAGRAM_PATH_RE.exec(path);
    const postId = match?.[1];
    if (postId === undefined) return null;
    return {
      platform: 'instagram',
      url: `https://www.instagram.com/p/${postId}/`,
      postId,
    };
  }

  if (host === 'youtube.com' || host === 'music.youtube.com') {
    let postId: string | undefined;
    if (path === '/watch') {
      const candidate = parsed.searchParams.get('v');
      if (candidate !== null && YOUTUBE_ID_RE.test(candidate)) postId = candidate;
    } else {
      const match = /^\/(?:shorts|live|embed)\/([A-Za-z0-9_-]{6,32})(?:\/|$)/.exec(path);
      postId = match?.[1];
    }
    if (postId === undefined) return null;
    return {
      platform: 'youtube',
      url: `https://www.youtube.com/watch?v=${postId}`,
      postId,
    };
  }

  if (host === 'youtu.be') {
    const postId = /^\/([A-Za-z0-9_-]{6,32})(?:\/|$)/.exec(path)?.[1];
    if (postId === undefined) return null;
    return {
      platform: 'youtube',
      url: `https://www.youtube.com/watch?v=${postId}`,
      postId,
    };
  }

  if (host === 'x.com' || host === 'twitter.com') {
    const match = X_STATUS_RE.exec(path);
    const handle = match?.[1];
    const postId = match?.[2];
    if (handle === undefined || postId === undefined) return null;
    return {
      platform: 'x',
      url: `https://x.com/${handle}/status/${postId}`,
      postId,
    };
  }

  return null;
}

/** SHA-256 over raw media bytes, lowercase hex. */
export function hashMediaBytes(bytes: Uint8Array | ArrayBuffer): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return bytesToHex(sha256(view));
}

/** SHA-256 over the UTF-8 encoding of a text post. */
export function hashMediaText(text: string): string {
  if (typeof text !== 'string') throw new TypeError('Text source must be a string');
  return bytesToHex(sha256(utf8ToBytes(text)));
}

export function hashReceiptSource(source: ReceiptSource): string {
  if (!isReceiptSourceKind(source.kind)) throw new TypeError('Unknown receipt source kind');
  if (source.kind === 'text') {
    if (typeof source.value !== 'string') throw new TypeError('Text source must be a string');
    return hashMediaText(source.value);
  }
  if (typeof source.value === 'string') throw new TypeError('Media source must be raw bytes');
  if (source.value.length === 0) throw new TypeError('Media source is empty');
  if (source.value.length > MAX_RECEIPT_SOURCE_BYTES) {
    throw new RangeError(`Media source exceeds ${MAX_RECEIPT_SOURCE_BYTES} bytes`);
  }
  return hashMediaBytes(source.value);
}

function isReceiptSourceKind(value: unknown): value is ReceiptSourceKind {
  return value === 'media' || value === 'text';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isTimestamp(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0;
}

/** Build canonical receipt content for a source. */
export function buildHydraReceiptContent(input: {
  readonly url: string;
  readonly source: ReceiptSource;
  readonly committedAt: number;
  readonly note?: string;
}): HydraReceiptContent {
  const anchor = normalizeSocialUrl(input.url);
  if (anchor === null) {
    throw new TypeError('Receipt URL must be an Instagram, YouTube or X post URL');
  }
  if (!isTimestamp(input.committedAt)) {
    throw new RangeError('Receipt timestamp must be a non-negative integer');
  }
  let note: string | undefined;
  if (input.note !== undefined) {
    if (typeof input.note !== 'string') throw new TypeError('Receipt note must be a string');
    const trimmed = input.note.trim();
    if (trimmed.length > MAX_RECEIPT_NOTE_CHARS) {
      throw new RangeError(`Receipt note exceeds ${MAX_RECEIPT_NOTE_CHARS} characters`);
    }
    note = trimmed.length > 0 ? trimmed : undefined;
  }

  const base = {
    v: HYDRA_RECEIPT_VERSION,
    type: HYDRA_RECEIPT_TYPE,
    platform: anchor.platform,
    url: anchor.url,
    post_id: anchor.postId,
    source_sha256: hashReceiptSource(input.source),
    source_kind: input.source.kind,
    committed_at: input.committedAt,
  } as const;
  return note === undefined ? base : { ...base, note };
}

export function encodeReceiptContent(content: HydraReceiptContent): string {
  return JSON.stringify(content);
}

/** Parse receipt content from a packet, returning null for anything malformed. */
export function parseHydraReceipt(packet: SporePacket): HydraReceiptContent | null {
  if (!isRecord(packet) || packet.kind !== 'receipt') return null;
  const content = packet.content;
  if (typeof content !== 'string' || content.length === 0 || content.length > 16_384) {
    return null;
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(content);
  } catch {
    return null;
  }
  if (!isRecord(parsed)) return null;
  for (const key of Object.keys(parsed)) {
    if (!RECEIPT_KEYS.has(key)) return null;
  }

  if (parsed['v'] !== HYDRA_RECEIPT_VERSION || parsed['type'] !== HYDRA_RECEIPT_TYPE) return null;
  if (!isSocialPlatform(parsed['platform'])) return null;
  if (typeof parsed['url'] !== 'string' || typeof parsed['post_id'] !== 'string') return null;
  if (typeof parsed['source_sha256'] !== 'string' || !SOURCE_HASH_RE.test(parsed['source_sha256'])) {
    return null;
  }
  if (!isReceiptSourceKind(parsed['source_kind'])) return null;
  if (!isTimestamp(parsed['committed_at'])) return null;
  if (parsed['note'] !== undefined) {
    if (
      typeof parsed['note'] !== 'string' ||
      parsed['note'].length === 0 ||
      parsed['note'].length > MAX_RECEIPT_NOTE_CHARS
    ) {
      return null;
    }
  }

  const anchor = normalizeSocialUrl(parsed['url']);
  if (anchor === null || anchor.platform !== parsed['platform']) return null;
  if (anchor.url !== parsed['url'] || anchor.postId !== parsed['post_id']) return null;

  const note = parsed['note'];
  const base = {
    v: HYDRA_RECEIPT_VERSION,
    type: HYDRA_RECEIPT_TYPE,
    platform: anchor.platform,
    url: anchor.url,
    post_id: anchor.postId,
    source_sha256: parsed['source_sha256'],
    source_kind: parsed['source_kind'],
    committed_at: parsed['committed_at'],
  } as const;
  return typeof note === 'string' ? { ...base, note } : base;
}

/**
 * Verify a receipt packet end-to-end: signature/PoW, canonical URL, source
 * digest shape, and the binding between `committed_at` and the signed packet
 * timestamp. Content tampering fails the signature check; a receipt that was
 * validly signed but internally inconsistent fails the matching checks.
 */
export function verifyHydraReceipt(packet: unknown): ReceiptVerification {
  const checks: ReceiptChecks = {
    signature: false,
    url: false,
    sourceHash: false,
    timestamp: false,
  };
  const verification: PacketVerificationResult = verifyPacket(packet);
  if (!verification.ok) {
    return {
      ok: false,
      packet: null,
      receipt: null,
      checks,
      reason: `${verification.reason}: ${verification.detail}`,
    };
  }
  const verified = verification.packet;
  const receipt = parseHydraReceipt(verified);
  if (receipt === null) {
    return {
      ok: false,
      packet: verified,
      receipt: null,
      checks: { ...checks, signature: true },
      reason: 'packet content is not a valid Hydra receipt',
    };
  }

  const anchor = normalizeSocialUrl(receipt.url);
  const urlOk =
    anchor !== null &&
    anchor.platform === receipt.platform &&
    anchor.url === receipt.url &&
    anchor.postId === receipt.post_id;
  const sourceHashOk = SOURCE_HASH_RE.test(receipt.source_sha256);
  const timestampOk = receipt.committed_at === verified.created_at;
  const ok = urlOk && sourceHashOk && timestampOk;

  return {
    ok,
    packet: verified,
    receipt,
    checks: {
      signature: true,
      url: urlOk,
      sourceHash: sourceHashOk,
      timestamp: timestampOk,
    },
    ...(ok ? {} : { reason: 'receipt fields do not match the signed packet' }),
  };
}

export interface HydraReceiptCreated {
  readonly packet: SporePacket;
  readonly receipt: HydraReceiptContent;
}

/** Mine, sign and return a `kind: 'receipt'` packet plus its parsed content. */
export async function createHydraReceipt(
  options: CreateHydraReceiptOptions,
): Promise<HydraReceiptCreated> {
  const committedAt = options.createdAt ?? Math.floor(Date.now() / 1000);
  const receipt = buildHydraReceiptContent({
    url: options.url,
    source: options.source,
    committedAt,
    ...(options.note !== undefined ? { note: options.note } : {}),
  });

  const packet = await sealPacket(
    {
      kind: 'receipt',
      content: encodeReceiptContent(receipt),
      created_at: committedAt,
    },
    options.identity,
    {
      ...(options.powBits !== undefined ? { powBits: options.powBits } : {}),
      ...(options.signal !== undefined ? { signal: options.signal } : {}),
      ...(options.onProgress !== undefined ? { onProgress: options.onProgress } : {}),
    },
  );

  return { packet, receipt };
}

export function formatReceiptTimestamp(seconds: number): string {
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return 'undated';
  return `${date.toISOString().slice(0, 19).replace('T', ' ')}Z`;
}

/** Plain-text proof for copying into a takedown appeal or archive. */
export function receiptProofText(packet: SporePacket): string {
  const receipt = parseHydraReceipt(packet);
  if (receipt === null) throw new TypeError('Packet is not a Hydra receipt');
  const lines = [
    `SPORE HYDRA RECEIPT · ${platformLabel(receipt.platform)}`,
    `external anchor : ${receipt.url}`,
    `post id         : ${receipt.post_id}`,
    `source sha256   : ${receipt.source_sha256}`,
    `source kind     : ${receipt.source_kind}`,
    `committed at    : ${formatReceiptTimestamp(receipt.committed_at)} (${receipt.committed_at})`,
    `author pubkey   : spore:0x${packet.pubkey}`,
    `packet id       : ${packet.id}`,
    `signature       : ${packet.sig}`,
    `pow             : ${packet.pow_bits} bits`,
  ];
  if (receipt.note !== undefined) lines.push(`note            : ${receipt.note}`);
  lines.push(
    'proof: this signed SPORE packet commits to the SHA-256 digest above at the timestamp shown. ' +
      'Anyone can verify it offline with verifyPacket() and the receipt fields.',
  );
  return lines.join('\n');
}
