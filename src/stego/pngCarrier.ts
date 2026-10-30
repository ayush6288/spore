/**
 * Parasitic PNG carrier.
 *
 * A SPORE packet bundle is JSON → UTF-8 → LZ → framed bytes:
 *
 *   "SPOR" | uint32 payload length | uint32 CRC32 | compressed payload
 *
 * The frame is written into the least-significant bit of the red, green and
 * blue channels of an RGBA buffer. Alpha is never touched: browsers can
 * premultiply alpha during canvas compositing, which would destroy LSB data.
 * The rendered canvas is exported as a lossless PNG so the bits survive.
 *
 * The canvas is only the presentation layer. All embedding/extraction logic
 * below operates on raw `Uint8ClampedArray` buffers and is fully testable
 * without a DOM.
 */

import { compressToUint8Array, decompressFromUint8Array } from 'lz-string';
import { verifyPacket, type SporePacket } from '../crypto/packet';

export const STEGO_MAGIC = new Uint8Array([0x53, 0x50, 0x4f, 0x52]); // "SPOR"
export const STEGO_MAGIC_TEXT = 'SPOR';
export const STEGO_VERSION = 1 as const;
export const STEGO_HEADER_BYTES = 12;
export const DEFAULT_STEGO_SIZE = 1080;
export const MIN_STEGO_SIZE = 256;
export const MAX_STEGO_SIZE = 4096;
const MAX_BUNDLE_PACKETS = 512;
const MAX_DECOMPRESSED_CHARS = 12_000_000;
const CHANNELS_PER_PIXEL = 3;

export interface StegoBundle {
  readonly v: typeof STEGO_VERSION;
  readonly created_at: number;
  readonly packets: SporePacket[];
}

export interface StegoDecodeResult {
  readonly packets: SporePacket[];
  readonly crcValid: boolean;
  readonly rejected: number;
  readonly reason?: string;
}

export interface FrameExtraction {
  readonly crcValid: boolean;
  readonly compressed: Uint8Array | null;
  readonly reason?: string;
}

export interface StegoEncodeOptions {
  /** Optional existing image used as the visible cover. */
  readonly coverImage?: HTMLImageElement | HTMLCanvasElement | ImageBitmap | OffscreenCanvas;
  /** Square output size. Defaults to 1080 and grows until the frame fits. */
  readonly size?: number;
  /** Bundle creation timestamp (Unix seconds). */
  readonly createdAt?: number;
  /** Injected for non-default documents (tests, embeds). */
  readonly document?: Document;
}

export type StegoImageSource =
  | Blob
  | ImageData
  | HTMLImageElement
  | HTMLCanvasElement
  | ImageBitmap
  | OffscreenCanvas;

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < 256; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) !== 0 ? (value >>> 1) ^ 0xedb88320 : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

/** Standard CRC-32/ISO-HDLC (same polynomial as PNG's ancillary chunks). */
export function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc = (CRC_TABLE[(crc ^ byte) & 0xff] ?? 0) ^ (crc >>> 8);
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function writeUint32BE(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
}

function readUint32BE(source: Uint8Array, offset: number): number {
  return (
    ((source[offset] ?? 0) << 24) |
    ((source[offset + 1] ?? 0) << 16) |
    ((source[offset + 2] ?? 0) << 8) |
    (source[offset + 3] ?? 0)
  ) >>> 0;
}

function hasMagic(bytes: Uint8Array): boolean {
  if (bytes.length < STEGO_HEADER_BYTES) return false;
  for (let index = 0; index < STEGO_MAGIC.length; index += 1) {
    if (bytes[index] !== STEGO_MAGIC[index]) return false;
  }
  return true;
}

/** Capacity in whole payload bytes for one RGBA buffer. */
export function rgbaCapacityBytes(rgba: Uint8ClampedArray | Uint8Array): number {
  if (rgba.length % 4 !== 0) {
    throw new RangeError('RGBA buffer length must be a multiple of 4');
  }
  return Math.floor(((rgba.length / 4) * CHANNELS_PER_PIXEL) / 8);
}

/** Wrap an already compressed payload in the SPOR frame. */
export function frameCompressedPayload(compressed: Uint8Array): Uint8Array {
  if (compressed.length > 0xffffffff) {
    throw new RangeError('Stego payload exceeds the uint32 length field');
  }
  const frame = new Uint8Array(STEGO_HEADER_BYTES + compressed.length);
  frame.set(STEGO_MAGIC, 0);
  writeUint32BE(frame, 4, compressed.length);
  writeUint32BE(frame, 8, crc32(compressed));
  frame.set(compressed, STEGO_HEADER_BYTES);
  return frame;
}

/**
 * Verify, canonicalize, compress and frame a packet bundle. Invalid packets
 * are refused before they can be embedded.
 */
export function buildStegoFrame(
  packets: readonly SporePacket[],
  options: { readonly createdAt?: number } = {},
): Uint8Array {
  if (!Array.isArray(packets) || packets.length === 0) {
    throw new TypeError('At least one packet is required');
  }
  if (packets.length > MAX_BUNDLE_PACKETS) {
    throw new RangeError(`A stego bundle may contain at most ${MAX_BUNDLE_PACKETS} packets`);
  }

  const verified: SporePacket[] = [];
  const seen = new Set<string>();
  for (const packet of packets) {
    const result = verifyPacket(packet);
    if (!result.ok) {
      throw new Error(`Refusing to embed an invalid packet: ${result.reason}: ${result.detail}`);
    }
    if (seen.has(result.packet.id)) continue;
    seen.add(result.packet.id);
    verified.push(result.packet);
  }

  const createdAt = options.createdAt ?? Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw new RangeError('Bundle createdAt must be a non-negative integer');
  }
  const bundle: StegoBundle = { v: STEGO_VERSION, created_at: createdAt, packets: verified };
  const compressed = compressToUint8Array(JSON.stringify(bundle));
  return frameCompressedPayload(compressed);
}

/** Copy the RGBA buffer and overwrite only RGB LSBs with the frame bits. */
export function embedFrameInRgba(
  coverRgba: Uint8ClampedArray,
  frame: Uint8Array,
): Uint8ClampedArray {
  const capacity = rgbaCapacityBytes(coverRgba);
  if (frame.length > capacity) {
    throw new RangeError(
      `Stego frame needs ${frame.length} bytes but the image holds ${capacity}`,
    );
  }

  const output = new Uint8ClampedArray(coverRgba);
  let bitIndex = 0;
  for (const byte of frame) {
    for (let shift = 7; shift >= 0; shift -= 1) {
      const pixel = Math.floor(bitIndex / CHANNELS_PER_PIXEL);
      const channel = bitIndex % CHANNELS_PER_PIXEL;
      const offset = pixel * 4 + channel;
      const bit = (byte >>> shift) & 1;
      output[offset] = ((output[offset] ?? 0) & 0xfe) | bit;
      bitIndex += 1;
    }
  }
  return output;
}

function readBytesAtBit(
  rgba: Uint8ClampedArray,
  byteCount: number,
  startBit = 0,
): Uint8Array | null {
  const neededBits = byteCount * 8;
  const capacityBits = Math.floor(rgba.length / 4) * CHANNELS_PER_PIXEL;
  if (startBit + neededBits > capacityBits) return null;

  const output = new Uint8Array(byteCount);
  let bitIndex = startBit;
  for (let index = 0; index < byteCount; index += 1) {
    let value = 0;
    for (let bit = 0; bit < 8; bit += 1) {
      const pixel = Math.floor(bitIndex / CHANNELS_PER_PIXEL);
      const channel = bitIndex % CHANNELS_PER_PIXEL;
      value = (value << 1) | ((rgba[pixel * 4 + channel] ?? 0) & 1);
      bitIndex += 1;
    }
    output[index] = value;
  }
  return output;
}

/** Read and validate the frame header/payload from an RGBA buffer. */
export function extractFrameFromRgba(rgba: Uint8ClampedArray): FrameExtraction {
  let capacity: number;
  try {
    capacity = rgbaCapacityBytes(rgba);
  } catch (error) {
    return {
      crcValid: false,
      compressed: null,
      reason: error instanceof Error ? error.message : String(error),
    };
  }
  if (capacity < STEGO_HEADER_BYTES) {
    return { crcValid: false, compressed: null, reason: 'image is too small for a stego header' };
  }

  const header = readBytesAtBit(rgba, STEGO_HEADER_BYTES);
  if (header === null) {
    return { crcValid: false, compressed: null, reason: 'image is too small for a stego header' };
  }
  if (!hasMagic(header)) {
    return { crcValid: false, compressed: null, reason: 'SPOR magic bytes not found' };
  }

  const length = readUint32BE(header, 4);
  if (length === 0) {
    return { crcValid: false, compressed: null, reason: 'payload length is zero' };
  }
  if (length > capacity - STEGO_HEADER_BYTES) {
    return {
      crcValid: false,
      compressed: null,
      reason: 'payload length exceeds image capacity',
    };
  }

  const compressed = readBytesAtBit(rgba, length, STEGO_HEADER_BYTES * 8);
  if (compressed === null) {
    return { crcValid: false, compressed: null, reason: 'payload is truncated' };
  }
  const expected = readUint32BE(header, 8);
  const actual = crc32(compressed);
  if (actual !== expected) {
    return { crcValid: false, compressed: null, reason: 'CRC32 checksum mismatch' };
  }
  return { crcValid: true, compressed };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Extract, verify and filter packets from one raw RGBA buffer. */
export function decodeStegoRgba(rgba: Uint8ClampedArray): StegoDecodeResult {
  const extraction = extractFrameFromRgba(rgba);
  if (!extraction.crcValid || extraction.compressed === null) {
    return {
      packets: [],
      crcValid: false,
      rejected: 0,
      ...(extraction.reason !== undefined ? { reason: extraction.reason } : {}),
    };
  }

  let json: string;
  try {
    json = decompressFromUint8Array(extraction.compressed);
  } catch {
    return {
      packets: [],
      crcValid: true,
      rejected: 0,
      reason: 'payload is not valid LZ data',
    };
  }
  if (typeof json !== 'string' || json.length === 0 || json.length > MAX_DECOMPRESSED_CHARS) {
    return {
      packets: [],
      crcValid: true,
      rejected: 0,
      reason: 'decompressed payload is empty or too large',
    };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return { packets: [], crcValid: true, rejected: 0, reason: 'payload is not valid JSON' };
  }
  if (!isRecord(parsed) || parsed['v'] !== STEGO_VERSION) {
    return { packets: [], crcValid: true, rejected: 0, reason: 'unsupported stego bundle' };
  }
  const createdAt = parsed['created_at'];
  const candidates = parsed['packets'];
  if (
    !Number.isSafeInteger(createdAt) ||
    (createdAt as number) < 0 ||
    !Array.isArray(candidates) ||
    candidates.length > MAX_BUNDLE_PACKETS
  ) {
    return { packets: [], crcValid: true, rejected: 0, reason: 'malformed stego bundle' };
  }

  const packets: SporePacket[] = [];
  const seen = new Set<string>();
  let rejected = 0;
  for (const candidate of candidates) {
    const verified = verifyPacket(candidate);
    if (!verified.ok) {
      rejected += 1;
      continue;
    }
    if (seen.has(verified.packet.id)) continue;
    seen.add(verified.packet.id);
    packets.push(verified.packet);
  }

  return {
    packets,
    crcValid: true,
    rejected,
    ...(rejected > 0 ? { reason: `${rejected} packet(s) failed verification` } : {}),
  };
}

function createCanvas(
  width: number,
  height: number,
  doc: Document | undefined,
): HTMLCanvasElement | OffscreenCanvas {
  const owner = doc ?? (typeof document === 'undefined' ? undefined : document);
  if (owner !== undefined) {
    const canvas = owner.createElement('canvas');
    canvas.width = width;
    canvas.height = height;
    return canvas;
  }
  if (typeof OffscreenCanvas !== 'undefined') {
    return new OffscreenCanvas(width, height);
  }
  throw new Error('This environment has no canvas implementation');
}

function get2dContext(canvas: HTMLCanvasElement | OffscreenCanvas): CanvasRenderingContext2D {
  const context = canvas.getContext('2d', { willReadFrequently: true });
  if (context === null) throw new Error('Canvas 2D context is unavailable');
  // OffscreenCanvas and HTMLCanvasElement share the 2D API surface here.
  return context as CanvasRenderingContext2D;
}

function drawCoverImage(
  context: CanvasRenderingContext2D,
  image: HTMLImageElement | HTMLCanvasElement | ImageBitmap | OffscreenCanvas,
  size: number,
): void {
  let sourceWidth = 0;
  let sourceHeight = 0;
  if (typeof HTMLImageElement !== 'undefined' && image instanceof HTMLImageElement) {
    sourceWidth = image.naturalWidth || image.width;
    sourceHeight = image.naturalHeight || image.height;
  } else {
    sourceWidth = image.width;
    sourceHeight = image.height;
  }
  if (sourceWidth <= 0 || sourceHeight <= 0) return;

  const scale = Math.max(size / sourceWidth, size / sourceHeight);
  const drawWidth = sourceWidth * scale;
  const drawHeight = sourceHeight * scale;
  context.drawImage(
    image as CanvasImageSource,
    (size - drawWidth) / 2,
    (size - drawHeight) / 2,
    drawWidth,
    drawHeight,
  );
}

function wrapLines(
  context: CanvasRenderingContext2D,
  text: string,
  maxWidth: number,
  maxLines: number,
): string[] {
  const words = text.trim().split(/\s+/).filter((word) => word.length > 0);
  if (words.length === 0) return ['field note'];
  const lines: string[] = [];
  let current = '';
  for (const word of words) {
    const candidate = current.length === 0 ? word : `${current} ${word}`;
    if (context.measureText(candidate).width <= maxWidth || current.length === 0) {
      current = candidate;
      continue;
    }
    lines.push(current);
    current = word;
    if (lines.length === maxLines - 1) break;
  }
  if (lines.length < maxLines && current.length > 0) lines.push(current);
  if (lines.length === maxLines && current.length > 0) {
    let last = lines[maxLines - 1] ?? '';
    while (last.length > 1 && context.measureText(`${last}…`).width > maxWidth) {
      last = last.slice(0, -1);
    }
    lines[maxLines - 1] = `${last}…`;
  }
  return lines;
}

const SANS_STACK =
  '"Avenir Next", "Futura", "Century Gothic", "Trebuchet MS", system-ui, sans-serif';
const MONO_STACK =
  'ui-monospace, "SFMono-Regular", "SF Mono", Menlo, Consolas, "Liberation Mono", monospace';

function drawStegoCard(
  canvas: HTMLCanvasElement | OffscreenCanvas,
  title: string,
  packetCount: number,
  createdAt: number,
  coverImage: StegoEncodeOptions['coverImage'],
): void {
  const size = canvas.width;
  const context = get2dContext(canvas);
  context.save();
  context.scale(size / 1080, size / 1080);

  if (coverImage !== undefined) {
    context.fillStyle = '#090d16';
    context.fillRect(0, 0, 1080, 1080);
    drawCoverImage(context, coverImage, 1080);
    const shade = context.createLinearGradient(0, 0, 0, 1080);
    shade.addColorStop(0, 'rgba(9, 13, 22, 0.74)');
    shade.addColorStop(0.35, 'rgba(9, 13, 22, 0.1)');
    shade.addColorStop(1, 'rgba(9, 13, 22, 0.86)');
    context.fillStyle = shade;
    context.fillRect(0, 0, 1080, 1080);
  } else {
    const background = context.createLinearGradient(0, 0, 1080, 1080);
    background.addColorStop(0, '#090d16');
    background.addColorStop(0.55, '#0b1320');
    background.addColorStop(1, '#071018');
    context.fillStyle = background;
    context.fillRect(0, 0, 1080, 1080);

    context.strokeStyle = 'rgba(0, 245, 155, 0.07)';
    context.lineWidth = 1;
    for (let line = 60; line < 1080; line += 60) {
      context.beginPath();
      context.moveTo(line, 0);
      context.lineTo(line, 1080);
      context.stroke();
      context.beginPath();
      context.moveTo(0, line);
      context.lineTo(1080, line);
      context.stroke();
    }

    context.strokeStyle = 'rgba(0, 245, 155, 0.34)';
    context.lineWidth = 2;
    context.beginPath();
    context.arc(805, 700, 210, 0, Math.PI * 2);
    context.stroke();
    context.strokeStyle = 'rgba(255, 184, 0, 0.22)';
    context.beginPath();
    context.arc(805, 700, 148, 0, Math.PI * 2);
    context.stroke();
    context.fillStyle = 'rgba(0, 245, 155, 0.12)';
    for (const [x, y, radius] of [
      [760, 650, 8],
      [838, 690, 5],
      [792, 744, 6],
      [862, 760, 3],
    ] as const) {
      context.beginPath();
      context.arc(x, y, radius, 0, Math.PI * 2);
      context.fill();
    }
  }

  context.fillStyle = '#00f59b';
  context.fillRect(78, 78, 54, 4);
  context.font = `600 22px ${MONO_STACK}`;
  context.letterSpacing = '4px';
  context.fillText('SPORE // FIELD TRANSMISSION', 78, 124);
  context.letterSpacing = '0px';

  context.fillStyle = '#eef7f2';
  context.font = `600 82px ${SANS_STACK}`;
  const lines = wrapLines(context, title, 820, 3);
  lines.forEach((line, index) => {
    context.fillText(line, 78, 300 + index * 96);
  });

  const date = new Date(createdAt * 1000);
  const stamp = Number.isNaN(date.getTime())
    ? 'undated'
    : date.toISOString().slice(0, 16).replace('T', ' ');
  context.fillStyle = 'rgba(238, 247, 242, 0.62)';
  context.font = `400 24px ${MONO_STACK}`;
  context.fillText(
    `${packetCount} packet${packetCount === 1 ? '' : 's'} · anchored ${stamp}Z`,
    78,
    978,
  );
  context.fillStyle = 'rgba(0, 245, 155, 0.78)';
  context.font = `500 20px ${MONO_STACK}`;
  context.fillText('LOSSLESS PNG · THE IMAGE IS THE CARRIER', 78, 1016);
  context.restore();
}

function canvasToPngBlob(canvas: HTMLCanvasElement | OffscreenCanvas): Promise<Blob> {
  if (typeof HTMLCanvasElement !== 'undefined' && canvas instanceof HTMLCanvasElement) {
    return new Promise<Blob>((resolve, reject) => {
      canvas.toBlob((blob) => {
        if (blob === null) reject(new Error('PNG encoding failed'));
        else resolve(blob);
      }, 'image/png');
    });
  }
  const offscreen = canvas as OffscreenCanvas;
  return offscreen.convertToBlob({ type: 'image/png' });
}

/**
 * Render a shareable card (or user cover), embed the signed packet bundle in
 * RGB LSBs, and return a lossless PNG Blob.
 */
export async function encodePacketsToStegoPng(
  packets: readonly SporePacket[],
  coverTitle = 'spore field note',
  options: StegoEncodeOptions = {},
): Promise<Blob> {
  const createdAt = options.createdAt ?? Math.floor(Date.now() / 1000);
  const frame = buildStegoFrame(packets, { createdAt });

  let size = options.size ?? DEFAULT_STEGO_SIZE;
  if (!Number.isSafeInteger(size) || size < MIN_STEGO_SIZE || size > MAX_STEGO_SIZE) {
    throw new RangeError(
      `Stego size must be an integer between ${MIN_STEGO_SIZE} and ${MAX_STEGO_SIZE}`,
    );
  }
  size = Math.ceil(size / 16) * 16;
  while (Math.floor((size * size * CHANNELS_PER_PIXEL) / 8) < frame.length) {
    const next = Math.ceil((size * 1.2) / 16) * 16;
    size = Math.min(MAX_STEGO_SIZE, next);
    if (size === MAX_STEGO_SIZE) break;
  }
  if (Math.floor((size * size * CHANNELS_PER_PIXEL) / 8) < frame.length) {
    throw new RangeError('Packet bundle is too large for a maximum-size SPORE carrier');
  }

  const canvas = createCanvas(size, size, options.document);
  drawStegoCard(canvas, coverTitle, packets.length, createdAt, options.coverImage);

  const context = get2dContext(canvas);
  const image = context.getImageData(0, 0, size, size);
  const embedded = embedFrameInRgba(image.data, frame);
  for (let index = 0; index < embedded.length; index += 4) {
    // The embedded copy already preserves alpha; this is an explicit guard.
    embedded[index + 3] = 255;
  }
  image.data.set(embedded);
  context.putImageData(image, 0, 0);

  return canvasToPngBlob(canvas);
}

async function imageBitmapFromBlob(blob: Blob): Promise<ImageBitmap> {
  if (typeof createImageBitmap !== 'function') {
    throw new Error('This browser cannot rasterize PNG blobs');
  }
  return createImageBitmap(blob);
}

function isImageData(value: unknown): value is ImageData {
  return (
    typeof ImageData !== 'undefined' &&
    value instanceof ImageData &&
    value.data instanceof Uint8ClampedArray
  );
}

function sourceDimensions(source: Exclude<StegoImageSource, Blob | ImageData>): {
  width: number;
  height: number;
} {
  if (typeof HTMLImageElement !== 'undefined' && source instanceof HTMLImageElement) {
    return { width: source.naturalWidth || source.width, height: source.naturalHeight || source.height };
  }
  return { width: source.width, height: source.height };
}

async function rasterizeStegoSource(source: StegoImageSource): Promise<ImageData> {
  if (isImageData(source)) return source;

  let drawable: CanvasImageSource;
  let width: number;
  let height: number;

  if (typeof Blob !== 'undefined' && source instanceof Blob) {
    const bitmap = await imageBitmapFromBlob(source);
    drawable = bitmap;
    width = bitmap.width;
    height = bitmap.height;
  } else {
    const candidate = source as Exclude<StegoImageSource, Blob | ImageData>;
    const dimensions = sourceDimensions(candidate);
    drawable = candidate as CanvasImageSource;
    width = dimensions.width;
    height = dimensions.height;
    if (typeof HTMLImageElement !== 'undefined' && candidate instanceof HTMLImageElement) {
      if (!candidate.complete) {
        await new Promise<void>((resolve, reject) => {
          candidate.addEventListener('load', () => resolve(), { once: true });
          candidate.addEventListener(
            'error',
            () => reject(new Error('Cover image failed to load')),
            { once: true },
          );
        });
      }
      if ('decode' in candidate) {
        try {
          await candidate.decode();
        } catch {
          // Some file:// contexts reject decode() on already-loaded images.
        }
      }
    }
  }

  if (width <= 0 || height <= 0) throw new Error('Stego image has no pixels');
  const canvas = createCanvas(width, height, undefined);
  const context = get2dContext(canvas);
  context.drawImage(drawable, 0, 0);
  return context.getImageData(0, 0, width, height);
}

/**
 * Decode a PNG/BLOB/ImageData carrier. CRC failure is reported in the result
 * rather than thrown, so the UI can distinguish tamper from a bad file.
 */
export async function decodePacketsFromStegoPng(
  fileOrImageData: StegoImageSource,
): Promise<StegoDecodeResult> {
  const image = await rasterizeStegoSource(fileOrImageData);
  return decodeStegoRgba(image.data);
}
