/**
 * SPORE video swarm primitives.
 *
 * A video is sliced into fixed-size chunks, each addressed by SHA-256. The
 * manifest's `media_id` is the SHA-256 of the complete binary and is bound to
 * the signed packet through `media_cid`, so every received chunk and the final
 * assembled blob can be verified without trusting the peer that served it.
 *
 * Chunks live in two tiers:
 *
 *   IndexedDB store `spore_video_chunks` (durable across reloads)
 *   an in-memory Map (works on locked-down `file://` origins)
 *
 * The memory tier is always written first, so playback and seeding work even
 * when IndexedDB is unavailable or a write is still in flight.
 */

import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '../crypto/encoding';
import {
  MAX_INLINE_MEDIA_BYTES,
  MAX_MEDIA_BYTES,
  MAX_MEDIA_CHUNKS,
  MAX_MEDIA_CHUNK_SIZE,
  validateMediaManifest,
  type MediaManifest,
} from '../crypto/packet';

export const DEFAULT_VIDEO_CHUNK_SIZE = 65_536;
export const VIDEO_DB_NAME = 'spore_video_v1';
export const VIDEO_DB_VERSION = 1;
export const VIDEO_STORE_NAME = 'spore_video_chunks';

const BASE64_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const BASE64_LOOKUP = (() => {
  const table = new Int16Array(128).fill(-1);
  for (let index = 0; index < BASE64_ALPHABET.length; index += 1) {
    table[BASE64_ALPHABET.charCodeAt(index)] = index;
  }
  return table;
})();

export interface VideoSliceOptions {
  readonly fileName: string;
  readonly mime: string;
  readonly sourceUrl?: string;
  readonly chunkSize?: number;
  /** Inline clips up to 1.5 MB so offline carriers can play with zero peers. */
  readonly inlineSmallVideos?: boolean;
}

export interface VideoSlice {
  readonly manifest: MediaManifest;
  readonly chunks: Uint8Array[];
}

export interface VideoChunkCacheOptions {
  readonly indexedDB?: IDBFactory | null;
  readonly dbName?: string;
  readonly storeName?: string;
}

export function sha256Hex(bytes: Uint8Array): string {
  return bytesToHex(sha256(bytes));
}

export function bytesToBase64(bytes: Uint8Array): string {
  let out = '';
  for (let offset = 0; offset < bytes.length; offset += 3) {
    const a = bytes[offset] ?? 0;
    const b = bytes[offset + 1];
    const c = bytes[offset + 2];
    const triple = (a << 16) | ((b ?? 0) << 8) | (c ?? 0);
    out += BASE64_ALPHABET[(triple >>> 18) & 0x3f];
    out += BASE64_ALPHABET[(triple >>> 12) & 0x3f];
    out += b === undefined ? '=' : BASE64_ALPHABET[(triple >>> 6) & 0x3f];
    out += c === undefined ? '=' : BASE64_ALPHABET[triple & 0x3f];
  }
  return out;
}

export function base64ToBytes(text: string): Uint8Array {
  if (typeof text !== 'string') throw new TypeError('base64 input must be a string');
  let clean = text.trim();
  if (clean.length === 0) return new Uint8Array(0);
  const padding = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
  if (padding > 0) clean = clean.slice(0, -padding);
  if (clean.length % 4 === 1) throw new TypeError('invalid base64 length');

  const out = new Uint8Array(Math.floor((clean.length * 3) / 4));
  let buffer = 0;
  let bits = 0;
  let written = 0;
  for (let index = 0; index < clean.length; index += 1) {
    const code = clean.charCodeAt(index);
    const value = code < 128 ? BASE64_LOOKUP[code] : -1;
    if (value === undefined || value < 0) throw new TypeError('invalid base64 character');
    buffer = (buffer << 6) | value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out[written] = (buffer >>> bits) & 0xff;
      written += 1;
    }
  }
  return out.subarray(0, written);
}

function base64DecodedLength(text: string): number | null {
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4 !== 0) return null;
  const padding = text.endsWith('==') ? 2 : text.endsWith('=') ? 1 : 0;
  return (text.length / 4) * 3 - padding;
}

function requestDone<T>(request: IDBRequest<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error ?? new Error('IndexedDB request failed'));
  });
}

function transactionDone(transaction: IDBTransaction): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error('IndexedDB transaction failed'));
    transaction.onabort = () => reject(transaction.error ?? new Error('IndexedDB transaction aborted'));
  });
}

function mediaCacheKey(mediaId: string, chunkIndex: number): string {
  return `${mediaId}:${chunkIndex}`;
}

/**
 * Dual-tier chunk cache. IndexedDB failures degrade silently to memory; a
 * quota or `file://` SecurityError must never break playback or seeding.
 */
export class VideoChunkCache {
  private readonly memory = new Map<string, Uint8Array>();
  private readonly factory: IDBFactory | null;
  private readonly dbName: string;
  private readonly storeName: string;
  private dbPromise: Promise<IDBDatabase | null> | null = null;

  constructor(options: VideoChunkCacheOptions = {}) {
    const configured =
      options.indexedDB !== undefined ? options.indexedDB : (globalThis.indexedDB ?? null);
    this.factory = configured;
    this.dbName = options.dbName ?? VIDEO_DB_NAME;
    this.storeName = options.storeName ?? VIDEO_STORE_NAME;
  }

  get memoryChunks(): number {
    return this.memory.size;
  }

  async put(mediaId: string, chunkIndex: number, bytes: Uint8Array): Promise<void> {
    if (!(bytes instanceof Uint8Array)) return;
    const key = mediaCacheKey(mediaId, chunkIndex);
    this.memory.set(key, bytes.slice());
    const db = await this.openDatabase();
    if (db === null) return;
    try {
      const tx = db.transaction(this.storeName, 'readwrite');
      tx.objectStore(this.storeName).put(bytes.slice(), key);
      await transactionDone(tx);
    } catch {
      // Quota or security failure: the memory tier remains authoritative.
    }
  }

  async get(mediaId: string, chunkIndex: number): Promise<Uint8Array | null> {
    const key = mediaCacheKey(mediaId, chunkIndex);
    const cached = this.memory.get(key);
    if (cached !== undefined) return cached.slice();
    const db = await this.openDatabase();
    if (db === null) return null;
    try {
      const tx = db.transaction(this.storeName, 'readonly');
      const result = await requestDone<unknown>(tx.objectStore(this.storeName).get(key));
      await transactionDone(tx);
      if (!(result instanceof Uint8Array) || result.length === 0) return null;
      const copy = result.slice();
      this.memory.set(key, copy);
      return copy.slice();
    } catch {
      return null;
    }
  }

  async list(mediaId: string): Promise<number[]> {
    const indices = new Set<number>();
    const prefix = `${mediaId}:`;
    for (const key of this.memory.keys()) {
      if (!key.startsWith(prefix)) continue;
      const suffix = Number(key.slice(prefix.length));
      if (Number.isSafeInteger(suffix) && suffix >= 0) indices.add(suffix);
    }
    const db = await this.openDatabase();
    if (db !== null) {
      try {
        const tx = db.transaction(this.storeName, 'readonly');
        const keys = await requestDone<IDBValidKey[]>(tx.objectStore(this.storeName).getAllKeys());
        await transactionDone(tx);
        for (const key of keys) {
          if (typeof key !== 'string' || !key.startsWith(prefix)) continue;
          const suffix = Number(key.slice(prefix.length));
          if (Number.isSafeInteger(suffix) && suffix >= 0) indices.add(suffix);
        }
      } catch {
        // Memory-only listing is still useful.
      }
    }
    return [...indices].sort((a, b) => a - b);
  }

  async deleteMedia(mediaId: string): Promise<void> {
    const prefix = `${mediaId}:`;
    for (const key of [...this.memory.keys()]) {
      if (key.startsWith(prefix)) this.memory.delete(key);
    }
    const db = await this.openDatabase();
    if (db === null) return;
    try {
      const tx = db.transaction(this.storeName, 'readwrite');
      const store = tx.objectStore(this.storeName);
      const keys = await requestDone<IDBValidKey[]>(store.getAllKeys());
      for (const key of keys) {
        if (typeof key === 'string' && key.startsWith(prefix)) store.delete(key);
      }
      await transactionDone(tx);
    } catch {
      // Nothing else to do: memory is already cleared.
    }
  }

  close(): void {
    const pending = this.dbPromise;
    this.dbPromise = null;
    void pending?.then((db) => db?.close()).catch(() => undefined);
  }

  private openDatabase(): Promise<IDBDatabase | null> {
    if (this.factory === null) return Promise.resolve(null);
    if (this.dbPromise !== null) return this.dbPromise;
    this.dbPromise = new Promise<IDBDatabase | null>((resolve) => {
      let settled = false;
      const finish = (db: IDBDatabase | null): void => {
        if (settled) return;
        settled = true;
        resolve(db);
      };
      try {
        const request = this.factory!.open(this.dbName, VIDEO_DB_VERSION);
        request.onupgradeneeded = () => {
          const db = request.result;
          if (!db.objectStoreNames.contains(this.storeName)) {
            db.createObjectStore(this.storeName);
          }
        };
        request.onsuccess = () => finish(request.result);
        request.onerror = () => finish(null);
        request.onblocked = () => finish(null);
      } catch {
        finish(null);
      }
    });
    return this.dbPromise;
  }
}

export const defaultVideoCache = new VideoChunkCache();

function resolveFileName(file: File | Blob, fallback: string): string {
  const candidate = (file as { name?: unknown }).name;
  if (typeof candidate === 'string' && candidate.trim().length > 0) {
    return candidate.trim().slice(0, 255);
  }
  return fallback;
}

function resolveMime(file: File | Blob, fileName: string): string {
  if (typeof file.type === 'string' && file.type.trim().length > 0) {
    return file.type.trim().toLowerCase();
  }
  const extension = fileName.toLowerCase().slice(fileName.lastIndexOf('.') + 1);
  const map: Record<string, string> = {
    mp4: 'video/mp4',
    m4v: 'video/mp4',
    webm: 'video/webm',
    mov: 'video/quicktime',
    ogv: 'video/ogg',
    mkv: 'video/x-matroska',
  };
  return map[extension] ?? 'application/octet-stream';
}

function assertChunkSize(chunkSize: number): number {
  if (
    !Number.isSafeInteger(chunkSize) ||
    chunkSize < 1 ||
    chunkSize > MAX_MEDIA_CHUNK_SIZE
  ) {
    throw new RangeError(`chunkSize must be an integer between 1 and ${MAX_MEDIA_CHUNK_SIZE}`);
  }
  return chunkSize;
}

/**
 * Pure slicing step: hash every chunk and the complete binary, then build the
 * manifest. No storage or DOM access, so it is safe in tests and workers.
 */
export function sliceVideoBytes(bytes: Uint8Array, options: VideoSliceOptions): VideoSlice {
  if (!(bytes instanceof Uint8Array)) throw new TypeError('video bytes must be a Uint8Array');
  if (bytes.length < 1) throw new RangeError('video is empty');
  if (bytes.length > MAX_MEDIA_BYTES) {
    throw new RangeError(`video exceeds the ${MAX_MEDIA_BYTES}-byte ceiling`);
  }
  const chunkSize = assertChunkSize(options.chunkSize ?? DEFAULT_VIDEO_CHUNK_SIZE);
  if (options.fileName.trim().length === 0) throw new TypeError('file name is required');
  if (options.mime.trim().length === 0) throw new TypeError('mime type is required');

  const totalChunks = Math.ceil(bytes.length / chunkSize);
  if (totalChunks > MAX_MEDIA_CHUNKS) {
    throw new RangeError(`video needs more than ${MAX_MEDIA_CHUNKS} chunks`);
  }
  const chunks: Uint8Array[] = [];
  const chunkHashes: string[] = [];
  for (let index = 0; index < totalChunks; index += 1) {
    const start = index * chunkSize;
    const chunk = bytes.slice(start, Math.min(start + chunkSize, bytes.length));
    chunks.push(chunk);
    chunkHashes.push(sha256Hex(chunk));
  }

  const mediaId = sha256Hex(bytes);
  const inline =
    options.inlineSmallVideos !== false && bytes.length <= MAX_INLINE_MEDIA_BYTES;
  const manifest = validateMediaManifest({
    media_id: mediaId,
    file_name: options.fileName,
    mime: options.mime,
    size: bytes.length,
    chunk_size: chunkSize,
    total_chunks: totalChunks,
    chunk_hashes: chunkHashes,
    ...(options.sourceUrl !== undefined && options.sourceUrl.length > 0
      ? { source_url: options.sourceUrl }
      : {}),
    ...(inline ? { inline_data_b64: bytesToBase64(bytes) } : {}),
  });
  return { manifest, chunks };
}

/** Read a File/Blob, slice it, and persist every chunk. */
export async function ingestVideoFile(
  file: File | Blob,
  sourceUrl?: string,
  options: {
    readonly chunkSize?: number;
    readonly inlineSmallVideos?: boolean;
    readonly cache?: VideoChunkCache;
  } = {},
): Promise<VideoSlice> {
  if (typeof file.arrayBuffer !== 'function') {
    throw new TypeError('video source must be a File or Blob');
  }
  const fileName = resolveFileName(file, `spore-reel-${Date.now()}.mp4`);
  const mime = resolveMime(file, fileName);
  const buffer = await file.arrayBuffer();
  const slice = sliceVideoBytes(new Uint8Array(buffer), {
    fileName,
    mime,
    ...(sourceUrl !== undefined && sourceUrl.trim().length > 0
      ? { sourceUrl: sourceUrl.trim() }
      : {}),
    ...(options.chunkSize !== undefined ? { chunkSize: options.chunkSize } : {}),
    ...(options.inlineSmallVideos !== undefined
      ? { inlineSmallVideos: options.inlineSmallVideos }
      : {}),
  });

  const cache = options.cache ?? defaultVideoCache;
  for (let index = 0; index < slice.chunks.length; index += 1) {
    const chunk = slice.chunks[index];
    if (chunk === undefined) continue;
    const stored = await verifyAndStoreChunk(slice.manifest, index, chunk, cache);
    if (!stored) throw new Error(`chunk ${index} failed local verification`);
  }
  return slice;
}

function expectedChunkLength(manifest: MediaManifest, chunkIndex: number): number {
  if (chunkIndex < manifest.total_chunks - 1) return manifest.chunk_size;
  return manifest.size - manifest.chunk_size * (manifest.total_chunks - 1);
}

/**
 * Verify one chunk against the manifest before touching storage. Mismatched or
 * oversized chunks are dropped without throwing, so a hostile peer cannot
 * wedge the receive loop.
 */
export async function verifyAndStoreChunk(
  manifest: MediaManifest,
  chunkIndex: number,
  rawBytes: Uint8Array,
  cache: VideoChunkCache = defaultVideoCache,
): Promise<boolean> {
  if (!Number.isSafeInteger(chunkIndex) || chunkIndex < 0) return false;
  if (chunkIndex >= manifest.total_chunks) return false;
  if (!(rawBytes instanceof Uint8Array)) return false;
  if (rawBytes.length !== expectedChunkLength(manifest, chunkIndex)) return false;
  const expected = manifest.chunk_hashes[chunkIndex];
  if (typeof expected !== 'string' || sha256Hex(rawBytes) !== expected) return false;
  await cache.put(manifest.media_id, chunkIndex, rawBytes);
  return true;
}

/** Decode and verify an inline clip, then seed its chunks locally. */
export async function importInlineMedia(
  manifest: MediaManifest,
  cache: VideoChunkCache = defaultVideoCache,
): Promise<boolean> {
  const inline = manifest.inline_data_b64;
  if (typeof inline !== 'string' || inline.length === 0) return false;
  if (base64DecodedLength(inline) !== manifest.size) return false;
  let bytes: Uint8Array;
  try {
    bytes = base64ToBytes(inline);
  } catch {
    return false;
  }
  if (bytes.length !== manifest.size || sha256Hex(bytes) !== manifest.media_id) return false;

  for (let index = 0; index < manifest.total_chunks; index += 1) {
    const start = index * manifest.chunk_size;
    const chunk = bytes.slice(start, Math.min(start + manifest.chunk_size, bytes.length));
    const stored = await verifyAndStoreChunk(manifest, index, chunk, cache);
    if (!stored) return false;
  }
  return true;
}

/** Every chunk index currently present in the local cache for this media. */
export async function availableChunks(
  manifest: MediaManifest,
  cache: VideoChunkCache = defaultVideoCache,
): Promise<number[]> {
  const listed = await cache.list(manifest.media_id);
  return listed.filter((index) => index >= 0 && index < manifest.total_chunks);
}

export async function hasCompleteMedia(
  manifest: MediaManifest,
  cache: VideoChunkCache = defaultVideoCache,
): Promise<boolean> {
  return (await availableChunks(manifest, cache)).length === manifest.total_chunks;
}

/**
 * Concatenate every verified chunk and return a playable Blob. Returns null if
 * any chunk is missing or fails its hash, never a partially trusted file.
 */
export async function assembleVideoBlob(
  manifest: MediaManifest,
  cache: VideoChunkCache = defaultVideoCache,
): Promise<Blob | null> {
  let parts: Uint8Array[] = [];
  let complete = true;
  for (let index = 0; index < manifest.total_chunks; index += 1) {
    const chunk = await cache.get(manifest.media_id, index);
    if (chunk === null) {
      complete = false;
      break;
    }
    if (chunk.length !== expectedChunkLength(manifest, index)) {
      complete = false;
      break;
    }
    if (sha256Hex(chunk) !== manifest.chunk_hashes[index]) {
      complete = false;
      break;
    }
    parts.push(chunk);
  }

  if (!complete) {
    // A small inline clip can bootstrap itself from the manifest alone.
    if (await importInlineMedia(manifest, cache)) {
      parts = [];
      for (let index = 0; index < manifest.total_chunks; index += 1) {
        const chunk = await cache.get(manifest.media_id, index);
        if (
          chunk === null ||
          chunk.length !== expectedChunkLength(manifest, index) ||
          sha256Hex(chunk) !== manifest.chunk_hashes[index]
        ) {
          return null;
        }
        parts.push(chunk);
      }
    } else {
      return null;
    }
  }

  let total = 0;
  for (const part of parts) total += part.length;
  if (total !== manifest.size) return null;
  const merged = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    merged.set(part, offset);
    offset += part.length;
  }
  if (sha256Hex(merged) !== manifest.media_id) return null;
  return new Blob([merged], { type: manifest.mime });
}

export async function deleteVideoMedia(
  mediaId: string,
  cache: VideoChunkCache = defaultVideoCache,
): Promise<void> {
  await cache.deleteMedia(mediaId);
}
