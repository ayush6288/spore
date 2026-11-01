/**
 * SPORE swarm.
 *
 * Online discovery runs two independent Trystero strategies at once:
 *
 *   Nostr relays (29 public relays by default)
 *   BitTorrent WebSocket trackers (5 public trackers by default)
 *
 * Every strategy joins `spore-global-v1` plus any number of normalized topic
 * rooms. The same peer may surface on both strategies; the registry below
 * deduplicates by Trystero peer id (shared across strategies).
 *
 * The manual fallback uses a plain RTCPeerConnection with no ICE servers. An
 * SDP offer or answer is LZ-compressed into a `spore-peer://...` string that a
 * user can send over WhatsApp, Signal, email or a QR code. Direct data-channel
 * messages are chunked because raw RTCDataChannel has no Trystero framing.
 */

import { compressToEncodedURIComponent, decompressFromEncodedURIComponent } from 'lz-string';
import { joinRoom as joinNostrRoom, defaultRelayUrls as defaultNostrRelays } from 'trystero/nostr';
import { joinRoom as joinTorrentRoom, defaultRelayUrls as defaultTorrentRelays } from '@trystero-p2p/torrent';
import type {
  JoinRoomCallbacks,
  JoinRoomConfig,
  MessageAction,
  Room,
} from 'trystero/nostr';
import {
  MAX_MEDIA_REQUEST_CHUNKS,
  WIRE_ACTION,
  encodeWireMessage,
  type MediaChunkMessage,
  type MediaHaveMessage,
  type MediaMessage,
  type MediaReqMessage,
} from './protocol';
import type { MediaManifest } from '../crypto/packet';
import {
  assembleVideoBlob,
  availableChunks,
  base64ToBytes as decodeBase64,
  bytesToBase64 as encodeBase64,
  defaultVideoCache,
  hasCompleteMedia,
  verifyAndStoreChunk,
  type VideoChunkCache,
} from '../media/videoSwarm';
import type { MeshPeerInfo, MeshTransportKind, OutboundMesh } from './transport';

export const DEFAULT_APP_ID = 'spore-v1';
export const GLOBAL_ROOM = 'spore-global-v1';
export const TOPIC_PREFIX = 'spore-topic-';
export const MANUAL_CODE_PREFIX = 'spore-peer://';
export const MANUAL_CHANNEL_LABEL = 'spore-manual-v1';

const MAX_MANUAL_CODE_CHARS = 200_000;
const MAX_MANUAL_SDP_CHARS = 160_000;
const MAX_MANUAL_MESSAGE_BYTES = 3_000_000;
const MANUAL_CHUNK_BYTES = 8 * 1024;
const MAX_MANUAL_CHUNKS = 512;
const MAX_REASSEMBLY_SLOTS = 16;
const MANUAL_ID_RE = /^[A-Za-z0-9_-]{8,80}$/;

type SignalingKind = 'nostr' | 'torrent';

interface RoomBinding {
  readonly kind: SignalingKind;
  readonly roomId: string;
  readonly room: Room;
  readonly action: MessageAction<string>;
}

interface PeerRecord {
  readonly id: string;
  readonly routes: Map<string, { readonly transport: MeshTransportKind; readonly room: string }>;
  /** Every transport this peer was ever seen on, for accurate leave telemetry. */
  readonly transports: Set<MeshTransportKind>;
  readonly since: number;
}

export interface SwarmOptions {
  readonly appId?: string;
  readonly globalRoom?: string;
  readonly nostrRelays?: readonly string[];
  readonly torrentRelays?: readonly string[];
  readonly redundancy?: number;
  readonly rtcConfig?: RTCConfiguration;
  /** ICE servers for manual links. Default [] so direct links work offline. */
  readonly manualIceServers?: RTCIceServer[];
  readonly maxWireChars?: number;
  readonly now?: () => number;
}

export type SwarmStatus = 'joined' | 'left';

export type SwarmEvent =
  | {
      readonly type: 'status';
      readonly status: SwarmStatus;
      readonly rooms: readonly string[];
      readonly relays: number;
    }
  | { readonly type: 'peer:join'; readonly peer: MeshPeerInfo }
  | {
      readonly type: 'peer:leave';
      readonly peerId: string;
      readonly transports: readonly MeshTransportKind[];
    }
  | { readonly type: 'error'; readonly message: string }
  | {
      readonly type: 'manual';
      readonly stage: 'offer' | 'answer' | 'connected' | 'closed' | 'error';
      readonly peerId?: string;
      readonly message?: string;
    };

export type SwarmEventListener = (event: SwarmEvent) => void;
export type SwarmMessageListener = (message: {
  readonly peerId: string;
  readonly data: string;
}) => void;

export interface ManualSignalPayload {
  readonly v: 1;
  readonly kind: 'offer' | 'answer';
  /** Offer/session id. Answers echo the offer id. */
  readonly id: string;
  /** Sender's manual peer id. */
  readonly from: string;
  /** Present on answers: the offerer's manual peer id. */
  readonly to?: string;
  readonly sdp: string;
}

export function normalizeTopicChannel(raw: string): string | null {
  let topic = raw.trim().toLowerCase();
  if (topic.startsWith(TOPIC_PREFIX)) topic = topic.slice(TOPIC_PREFIX.length);
  const slug = topic
    .replace(/[^a-z0-9._-]+/g, '-')
    .replace(/^[._-]+|[._-]+$/g, '')
    .slice(0, 48);
  if (slug.length < 2) return null;
  return `${TOPIC_PREFIX}${slug}`;
}

export function parseTopicChannels(raw: string): string[] {
  const rooms: string[] = [];
  const seen = new Set<string>();
  for (const piece of raw.split(/[,\s]+/)) {
    const room = normalizeTopicChannel(piece);
    if (room === null || seen.has(room)) continue;
    seen.add(room);
    rooms.push(room);
  }
  return rooms;
}

export function roomIdsFor(topics: readonly string[], globalRoom: string = GLOBAL_ROOM): string[] {
  const rooms = [globalRoom];
  const seen = new Set(rooms);
  for (const topic of topics) {
    if (topic.trim() === globalRoom) continue;
    const room = normalizeTopicChannel(topic);
    if (room === null || room === globalRoom || seen.has(room)) continue;
    seen.add(room);
    rooms.push(room);
  }
  return rooms;
}

function sanitizeRelays(urls: readonly string[] | undefined, fallback: readonly string[]): string[] {
  const source = urls ?? fallback;
  const seen = new Set<string>();
  const clean: string[] = [];
  for (const raw of source) {
    const url = raw.trim();
    if (!/^wss?:\/\//i.test(url) || seen.has(url)) continue;
    seen.add(url);
    clean.push(url);
  }
  return clean;
}

function assertManualId(value: string, label: string): string {
  if (!MANUAL_ID_RE.test(value)) {
    throw new TypeError(`${label} must be 8-80 URL-safe characters`);
  }
  return value;
}

export function encodeManualSignalCode(payload: ManualSignalPayload): string {
  if (payload.v !== 1) throw new TypeError('Unsupported manual signal version');
  if (payload.kind !== 'offer' && payload.kind !== 'answer') {
    throw new TypeError('Manual signal kind must be offer or answer');
  }
  assertManualId(payload.id, 'Manual signal id');
  assertManualId(payload.from, 'Manual signal sender');
  if (payload.kind === 'answer') {
    if (payload.to === undefined) throw new TypeError('Manual answer requires a target');
    assertManualId(payload.to, 'Manual signal target');
  }
  if (
    typeof payload.sdp !== 'string' ||
    payload.sdp.length === 0 ||
    payload.sdp.length > MAX_MANUAL_SDP_CHARS
  ) {
    throw new TypeError('Manual signal SDP is empty or too large');
  }
  const encoded = compressToEncodedURIComponent(JSON.stringify(payload));
  if (encoded.length === 0) throw new Error('Manual signal compression failed');
  if (encoded.length > MAX_MANUAL_CODE_CHARS) throw new Error('Manual signal code is too large');
  return `${MANUAL_CODE_PREFIX}${encoded}`;
}

export function decodeManualSignalCode(code: string): ManualSignalPayload | null {
  if (typeof code !== 'string') return null;
  const compact = code.replace(/\s+/g, '');
  if (!compact.startsWith(MANUAL_CODE_PREFIX)) return null;
  const encoded = compact.slice(MANUAL_CODE_PREFIX.length);
  if (encoded.length === 0 || encoded.length > MAX_MANUAL_CODE_CHARS) return null;
  const json = decompressFromEncodedURIComponent(encoded);
  if (json === null || json.length === 0) return null;

  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return null;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return null;
  const record = parsed as Record<string, unknown>;
  if (record['v'] !== 1) return null;
  const kind = record['kind'];
  const id = record['id'];
  const from = record['from'];
  const sdp = record['sdp'];
  const to = record['to'];
  if (kind !== 'offer' && kind !== 'answer') return null;
  if (typeof id !== 'string' || !MANUAL_ID_RE.test(id)) return null;
  if (typeof from !== 'string' || !MANUAL_ID_RE.test(from)) return null;
  if (typeof sdp !== 'string' || sdp.length === 0 || sdp.length > MAX_MANUAL_SDP_CHARS) {
    return null;
  }
  if (kind === 'answer') {
    if (typeof to !== 'string' || !MANUAL_ID_RE.test(to)) return null;
    return { v: 1, kind, id, from, to, sdp };
  }
  return { v: 1, kind, id, from, sdp };
}

function randomManualId(prefix: string): string {
  const bytes = new Uint8Array(12);
  const cryptoApi = globalThis.crypto;
  if (typeof cryptoApi?.getRandomValues === 'function') {
    cryptoApi.getRandomValues(bytes);
  } else {
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Math.floor(Math.random() * 256);
    }
  }
  let hex = '';
  for (const byte of bytes) hex += byte.toString(16).padStart(2, '0');
  return `${prefix}${hex}`;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const stride = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += stride) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + stride));
  }
  return btoa(binary);
}

function base64ToBytes(text: string): Uint8Array {
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function waitForIceGathering(pc: RTCPeerConnection, timeoutMs = 3_000): Promise<void> {
  if (pc.iceGatheringState === 'complete') return Promise.resolve();
  return new Promise<void>((resolve) => {
    let finished = false;
    const finish = (): void => {
      if (finished) return;
      finished = true;
      clearTimeout(timer);
      pc.removeEventListener('icegatheringstatechange', onState);
      pc.removeEventListener('icecandidate', onCandidate);
      resolve();
    };
    const onState = (): void => {
      if (pc.iceGatheringState === 'complete') finish();
    };
    const onCandidate = (event: RTCPeerConnectionIceEvent): void => {
      if (event.candidate === null) finish();
    };
    const timer = setTimeout(finish, timeoutMs);
    pc.addEventListener('icegatheringstatechange', onState);
    pc.addEventListener('icecandidate', onCandidate);
  });
}

function manualError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

interface ManualChunkFrame {
  readonly v: 1;
  readonly t: 'chunk';
  readonly m: string;
  readonly i: number;
  readonly n: number;
  readonly d: string;
}

interface ManualSession {
  readonly id: string;
  readonly localId: string;
  readonly role: 'offer' | 'answer';
  readonly pc: RTCPeerConnection;
  channel: RTCDataChannel | null;
  remoteId: string | null;
  answerApplied: boolean;
  opened: boolean;
  closed: boolean;
}

interface Reassembly {
  readonly total: number;
  readonly parts: Uint8Array[];
  next: number;
  bytes: number;
}

export interface ManualSignalingOptions {
  readonly iceServers?: RTCIceServer[];
  readonly onOpen: (peerId: string) => void;
  readonly onClose: (peerId: string) => void;
  readonly onMessage: (peerId: string, data: string) => void;
  readonly onStage: (
    stage: 'offer' | 'answer' | 'connected' | 'closed' | 'error',
    message?: string,
    peerId?: string,
  ) => void;
}

/**
 * One manual RTCPeerConnection control surface. Codes are always exchanged
 * out of band; this class makes no network requests of its own.
 */
export class ManualSignaling {
  private readonly options: ManualSignalingOptions;
  private readonly selfId: string;
  private readonly sessions = new Set<ManualSession>();
  private readonly reassembly = new Map<string, Reassembly>();
  private messageSeq = 0;

  constructor(options: ManualSignalingOptions) {
    this.options = options;
    this.selfId = randomManualId('p');
  }

  get localId(): string {
    return this.selfId;
  }

  async createOffer(): Promise<string> {
    const session = this.createSession('offer');
    session.remoteId = null;
    try {
      const channel = session.pc.createDataChannel(MANUAL_CHANNEL_LABEL, { ordered: true });
      this.attachChannel(session, channel);

      const offer = await session.pc.createOffer();
      await session.pc.setLocalDescription(offer);
      await waitForIceGathering(session.pc);
      const sdp = session.pc.localDescription?.sdp;
      if (sdp === undefined || sdp.length === 0) {
        throw new Error('WebRTC did not produce an offer SDP');
      }
      const code = encodeManualSignalCode({
        v: 1,
        kind: 'offer',
        id: session.id,
        from: this.selfId,
        sdp,
      });
      this.options.onStage('offer', `offer ready · ${code.length} chars`);
      return code;
    } catch (error) {
      this.closeSession(session, manualError(error));
      throw error;
    }
  }

  async acceptOffer(code: string): Promise<string> {
    const payload = decodeManualSignalCode(code);
    if (payload === null) throw new Error('This is not a valid spore-peer invite code');
    if (payload.kind !== 'offer') throw new Error('Expected an offer code, not an answer');

    const session = this.createSession('answer', payload.id);
    session.remoteId = payload.from;
    try {
      session.pc.ondatachannel = (event) => {
        this.attachChannel(session, event.channel);
      };

      await session.pc.setRemoteDescription({ type: 'offer', sdp: payload.sdp });
      const answer = await session.pc.createAnswer();
      await session.pc.setLocalDescription(answer);
      await waitForIceGathering(session.pc);
      const sdp = session.pc.localDescription?.sdp;
      if (sdp === undefined || sdp.length === 0) {
        throw new Error('WebRTC did not produce an answer SDP');
      }
      const answerCode = encodeManualSignalCode({
        v: 1,
        kind: 'answer',
        id: payload.id,
        from: this.selfId,
        to: payload.from,
        sdp,
      });
      this.options.onStage('answer', `answer ready · ${answerCode.length} chars`, payload.from);
      return answerCode;
    } catch (error) {
      this.closeSession(session, manualError(error));
      throw error;
    }
  }

  async applyAnswer(code: string): Promise<void> {
    const payload = decodeManualSignalCode(code);
    if (payload === null) throw new Error('This is not a valid spore-peer answer code');
    if (payload.kind !== 'answer') throw new Error('Expected an answer code, not an offer');
    if (payload.to !== this.selfId) throw new Error('This answer belongs to a different invite');

    let target: ManualSession | null = null;
    for (const session of this.sessions) {
      if (session.role === 'offer' && session.id === payload.id && !session.answerApplied) {
        target = session;
        break;
      }
    }
    if (target === null) throw new Error('No pending invite matches this answer');

    target.remoteId = payload.from;
    try {
      await target.pc.setRemoteDescription({ type: 'answer', sdp: payload.sdp });
    } catch (error) {
      this.closeSession(target, manualError(error));
      throw error;
    }
    target.answerApplied = true;
    this.options.onStage('answer', 'answer applied · waiting for channel', payload.from);
  }

  isPeerConnected(peerId: string): boolean {
    for (const session of this.sessions) {
      if (
        session.remoteId === peerId &&
        session.opened &&
        !session.closed &&
        session.channel?.readyState === 'open'
      ) {
        return true;
      }
    }
    return false;
  }

  send(peerId: string, data: string): boolean {
    const session = this.findOpenSession(peerId);
    if (session === null || session.channel === null) return false;
    const bytes = new TextEncoder().encode(data);
    if (bytes.length > MAX_MANUAL_MESSAGE_BYTES) {
      this.options.onStage('error', 'direct message exceeds the 3 MB ceiling', peerId);
      return false;
    }
    const total = Math.max(1, Math.ceil(bytes.length / MANUAL_CHUNK_BYTES));
    if (total > MAX_MANUAL_CHUNKS) {
      this.options.onStage('error', 'direct message needs too many chunks', peerId);
      return false;
    }
    const messageId = `${this.selfId}-${++this.messageSeq}`;
    for (let index = 0; index < total; index += 1) {
      const start = index * MANUAL_CHUNK_BYTES;
      const frame: ManualChunkFrame = {
        v: 1,
        t: 'chunk',
        m: messageId,
        i: index,
        n: total,
        d: bytesToBase64(bytes.subarray(start, start + MANUAL_CHUNK_BYTES)),
      };
      try {
        session.channel.send(JSON.stringify(frame));
      } catch (error) {
        this.options.onStage(
          'error',
          error instanceof Error ? error.message : String(error),
          peerId,
        );
        return false;
      }
    }
    return true;
  }

  closeAll(): void {
    for (const session of [...this.sessions]) {
      this.closeSession(session, 'closed');
    }
    this.reassembly.clear();
  }

  private createSession(role: 'offer' | 'answer', id?: string): ManualSession {
    if (typeof RTCPeerConnection === 'undefined') {
      throw new Error('WebRTC is unavailable in this browser');
    }
    const pc = new RTCPeerConnection({
      iceServers: this.options.iceServers ?? [],
    });
    const session: ManualSession = {
      id: id ?? randomManualId('o'),
      localId: this.selfId,
      role,
      pc,
      channel: null,
      remoteId: null,
      answerApplied: false,
      opened: false,
      closed: false,
    };
    this.sessions.add(session);

    pc.addEventListener('connectionstatechange', () => {
      if (pc.connectionState === 'failed' || pc.connectionState === 'closed') {
        this.closeSession(session, `connection ${pc.connectionState}`);
      }
    });
    pc.addEventListener('iceconnectionstatechange', () => {
      if (pc.iceConnectionState === 'failed') {
        this.closeSession(session, 'ICE failed');
      }
    });
    return session;
  }

  private attachChannel(session: ManualSession, channel: RTCDataChannel): void {
    if (session.channel !== null && session.channel !== channel) {
      try {
        session.channel.close();
      } catch {
        // already closed
      }
    }
    session.channel = channel;
    channel.binaryType = 'arraybuffer';
    channel.addEventListener('open', () => {
      const peerId = session.remoteId;
      if (peerId === null) {
        this.closeSession(session, 'direct channel opened without a peer identity');
        return;
      }
      session.opened = true;
      this.options.onStage('connected', 'direct data channel open', peerId);
      this.options.onOpen(peerId);
    });
    channel.addEventListener('close', () => {
      this.closeSession(session, 'direct channel closed');
    });
    channel.addEventListener('error', () => {
      this.options.onStage(
        'error',
        'direct data channel error',
        session.remoteId ?? undefined,
      );
    });
    channel.addEventListener('message', (event: MessageEvent<unknown>) => {
      const peerId = session.remoteId;
      if (peerId === null || typeof event.data !== 'string') return;
      this.receiveFrame(peerId, event.data);
    });
  }

  private receiveFrame(peerId: string, raw: string): void {
    if (raw.length > 64_000) {
      this.options.onStage('error', 'oversized direct frame rejected', peerId);
      return;
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      this.options.onStage('error', 'non-JSON direct frame rejected', peerId);
      return;
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) return;
    const frame = parsed as Record<string, unknown>;
    if (frame['v'] !== 1 || frame['t'] !== 'chunk') return;
    const messageId = frame['m'];
    const index = frame['i'];
    const total = frame['n'];
    const data = frame['d'];
    if (
      typeof messageId !== 'string' ||
      messageId.length === 0 ||
      messageId.length > 100 ||
      typeof index !== 'number' ||
      !Number.isSafeInteger(index) ||
      index < 0 ||
      typeof total !== 'number' ||
      !Number.isSafeInteger(total) ||
      total < 1 ||
      total > MAX_MANUAL_CHUNKS ||
      index >= total ||
      typeof data !== 'string' ||
      data.length > 12_000
    ) {
      this.options.onStage('error', 'malformed direct frame rejected', peerId);
      return;
    }

    const key = `${peerId}:${messageId}`;
    let state = this.reassembly.get(key);
    if (state === undefined) {
      if (this.reassembly.size >= MAX_REASSEMBLY_SLOTS) {
        const oldest = this.reassembly.keys().next().value;
        if (oldest !== undefined) this.reassembly.delete(oldest);
      }
      state = { total, parts: [], next: 0, bytes: 0 };
      this.reassembly.set(key, state);
    }
    if (state.total !== total || index !== state.next) {
      this.reassembly.delete(key);
      this.options.onStage('error', 'out-of-order direct frame rejected', peerId);
      return;
    }

    let part: Uint8Array;
    try {
      part = base64ToBytes(data);
    } catch {
      this.reassembly.delete(key);
      this.options.onStage('error', 'invalid direct frame encoding', peerId);
      return;
    }
    state.bytes += part.length;
    if (state.bytes > MAX_MANUAL_MESSAGE_BYTES) {
      this.reassembly.delete(key);
      this.options.onStage('error', 'direct message exceeds the 3 MB ceiling', peerId);
      return;
    }
    state.parts.push(part);
    state.next += 1;
    if (state.next < state.total) return;

    this.reassembly.delete(key);
    const merged = new Uint8Array(state.bytes);
    let offset = 0;
    for (const chunk of state.parts) {
      merged.set(chunk, offset);
      offset += chunk.length;
    }
    let text: string;
    try {
      text = new TextDecoder('utf-8', { fatal: true }).decode(merged);
    } catch {
      this.options.onStage('error', 'direct message is not valid UTF-8', peerId);
      return;
    }
    this.options.onMessage(peerId, text);
  }

  private findOpenSession(peerId: string): ManualSession | null {
    for (const session of this.sessions) {
      if (
        session.remoteId === peerId &&
        session.opened &&
        !session.closed &&
        session.channel?.readyState === 'open'
      ) {
        return session;
      }
    }
    return null;
  }

  private closeSession(session: ManualSession, reason: string): void {
    if (session.closed) return;
    session.closed = true;
    this.sessions.delete(session);
    const peerId = session.remoteId;
    if (peerId !== null) {
      const prefix = `${peerId}:`;
      for (const key of [...this.reassembly.keys()]) {
        if (key.startsWith(prefix)) this.reassembly.delete(key);
      }
    }
    try {
      session.channel?.close();
    } catch {
      // already closed
    }
    try {
      session.pc.close();
    } catch {
      // already closed
    }
    if (peerId !== null) {
      this.options.onStage('closed', reason, peerId);
      this.options.onClose(peerId);
    }
  }
}

export class Swarm implements OutboundMesh {
  private readonly appId: string;
  private readonly globalRoom: string;
  private readonly nostrRelays: string[];
  private readonly torrentRelays: string[];
  private readonly redundancy: number;
  private readonly rtcConfig: RTCConfiguration | undefined;
  private readonly maxWireChars: number;
  private readonly now: () => number;
  private readonly manual: ManualSignaling;

  private readonly bindings: RoomBinding[] = [];
  private readonly peers = new Map<string, PeerRecord>();
  private readonly eventListeners = new Set<SwarmEventListener>();
  private readonly messageListeners = new Set<SwarmMessageListener>();
  private joined = false;

  constructor(options: SwarmOptions = {}) {
    this.appId = options.appId ?? DEFAULT_APP_ID;
    this.globalRoom = options.globalRoom ?? GLOBAL_ROOM;
    this.nostrRelays = sanitizeRelays(options.nostrRelays, defaultNostrRelays);
    this.torrentRelays = sanitizeRelays(options.torrentRelays, defaultTorrentRelays);
    this.redundancy = options.redundancy ?? 5;
    if (!Number.isSafeInteger(this.redundancy) || this.redundancy < 1) {
      throw new RangeError('redundancy must be a positive integer');
    }
    this.rtcConfig = options.rtcConfig;
    this.maxWireChars = options.maxWireChars ?? 3_000_000;
    this.now = options.now ?? Date.now;

    this.manual = new ManualSignaling({
      ...(options.manualIceServers !== undefined
        ? { iceServers: options.manualIceServers }
        : {}),
      onOpen: (peerId) => {
        this.registerPeer(peerId, 'manual', 'direct');
      },
      onClose: (peerId) => {
        this.unregisterPeer(peerId, 'manual', 'direct');
      },
      onMessage: (peerId, data) => {
        this.dispatchMessage(peerId, data);
      },
      onStage: (stage, message, peerId) => {
        this.emit({
          type: 'manual',
          stage,
          ...(message !== undefined ? { message } : {}),
          ...(peerId !== undefined ? { peerId } : {}),
        });
      },
    });
  }

  get isJoined(): boolean {
    return this.joined;
  }

  get relayCount(): number {
    return this.nostrRelays.length + this.torrentRelays.length;
  }

  get rooms(): string[] {
    return [...new Set(this.bindings.map((binding) => binding.roomId))];
  }

  /** Join the global room plus normalized topic rooms on both strategies. */
  join(topics: readonly string[] = []): { rooms: string[]; relays: number } {
    if (this.joined) return { rooms: this.rooms, relays: this.relayCount };
    const roomIds = roomIdsFor(topics, this.globalRoom);
    const strategies: Array<{
      readonly kind: SignalingKind;
      readonly relays: string[];
      readonly join: (
        config: JoinRoomConfig,
        roomId: string,
        callbacks?: JoinRoomCallbacks,
      ) => Room;
    }> = [
      { kind: 'nostr', relays: this.nostrRelays, join: joinNostrRoom },
      { kind: 'torrent', relays: this.torrentRelays, join: joinTorrentRoom },
    ];

    for (const strategy of strategies) {
      if (strategy.relays.length === 0) continue;
      const config: JoinRoomConfig = {
        appId: this.appId,
        relayConfig: {
          urls: strategy.relays,
          redundancy: Math.min(this.redundancy, strategy.relays.length),
          warnOnRelayFailure: false,
        },
        ...(this.rtcConfig !== undefined ? { rtcConfig: this.rtcConfig } : {}),
      };

      for (const roomId of roomIds) {
        try {
          const room = strategy.join(config, roomId, {
            onJoinError: (details) => {
              this.emit({
                type: 'error',
                message: `${strategy.kind} ${details.roomId}: ${details.error}`,
              });
            },
          });
          const action = room.makeAction<string>(WIRE_ACTION);
          action.onMessage = (data, context) => {
            this.registerPeer(context.peerId, strategy.kind, roomId);
            this.dispatchMessage(context.peerId, data);
          };
          room.onPeerJoin = (peerId) => {
            this.registerPeer(peerId, strategy.kind, roomId);
          };
          room.onPeerLeave = (peerId) => {
            this.unregisterPeer(peerId, strategy.kind, roomId);
          };
          this.bindings.push({ kind: strategy.kind, roomId, room, action });
        } catch (error) {
          this.emit({
            type: 'error',
            message: `${strategy.kind} ${roomId}: ${
              error instanceof Error ? error.message : String(error)
            }`,
          });
        }
      }
    }

    this.joined = this.bindings.length > 0;
    const rooms = this.rooms;
    this.emit({
      type: 'status',
      status: this.joined ? 'joined' : 'left',
      rooms,
      relays: this.relayCount,
    });
    return { rooms, relays: this.relayCount };
  }

  /** Leave signaling only; manual direct peers remain connected. */
  async leaveSignaling(): Promise<void> {
    if (!this.joined && this.bindings.length === 0) return;
    const bindings = this.bindings.splice(0, this.bindings.length);
    this.joined = false;
    for (const binding of bindings) {
      binding.room.onPeerJoin = null;
      binding.room.onPeerLeave = null;
      binding.action.onMessage = null;
    }
    for (const peerId of [...this.peers.keys()]) {
      const record = this.peers.get(peerId);
      if (record === undefined) continue;
      for (const [key, route] of [...record.routes]) {
        if (route.transport !== 'manual') record.routes.delete(key);
      }
      if (record.routes.size === 0) {
        this.peers.delete(peerId);
        this.emit({
          type: 'peer:leave',
          peerId,
          transports: [...record.transports],
        });
      }
    }
    await Promise.allSettled(bindings.map((binding) => binding.room.leave()));
    this.emit({ type: 'status', status: 'left', rooms: [], relays: this.relayCount });
  }

  async destroy(): Promise<void> {
    this.manual.closeAll();
    await this.leaveSignaling();
    this.peers.clear();
    this.eventListeners.clear();
    this.messageListeners.clear();
  }

  peerIds(): string[] {
    return [...this.peers.keys()];
  }

  peersInfo(): MeshPeerInfo[] {
    return [...this.peers.values()]
      .map((record) => {
        const transports = new Set<MeshTransportKind>();
        const rooms = new Set<string>();
        for (const route of record.routes.values()) {
          transports.add(route.transport);
          rooms.add(route.room);
        }
        return {
          id: record.id,
          transports: [...transports],
          rooms: [...rooms],
          since: record.since,
        };
      })
      .sort((a, b) => a.since - b.since || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
  }

  async send(peerId: string, data: string): Promise<boolean> {
    if (typeof data !== 'string' || data.length === 0 || data.length > this.maxWireChars) {
      return false;
    }
    if (this.manual.isPeerConnected(peerId)) {
      if (this.manual.send(peerId, data)) return true;
    }
    for (const binding of this.bindings) {
      if (binding.room.getPeers()[peerId] === undefined) continue;
      try {
        await binding.action.send(data, { target: peerId });
        return true;
      } catch {
        // Try the next transport/room route.
      }
    }
    return false;
  }

  broadcast(data: string, except: Iterable<string> = []): void {
    const excluded = new Set(except);
    for (const peerId of this.peers.keys()) {
      if (excluded.has(peerId)) continue;
      void this.send(peerId, data);
    }
  }

  onEvent(listener: SwarmEventListener): () => void {
    this.eventListeners.add(listener);
    return () => {
      this.eventListeners.delete(listener);
    };
  }

  onMessage(listener: SwarmMessageListener): () => void {
    this.messageListeners.add(listener);
    return () => {
      this.messageListeners.delete(listener);
    };
  }

  createManualOffer(): Promise<string> {
    return this.manual.createOffer();
  }

  acceptManualOffer(code: string): Promise<string> {
    return this.manual.acceptOffer(code);
  }

  applyManualAnswer(code: string): Promise<void> {
    return this.manual.applyAnswer(code);
  }

  private registerPeer(peerId: string, transport: MeshTransportKind, room: string): void {
    if (typeof peerId !== 'string' || peerId.length === 0) return;
    const key = `${transport}:${room}`;
    let record = this.peers.get(peerId);
    if (record === undefined) {
      record = {
        id: peerId,
        routes: new Map([[key, { transport, room }]]),
        transports: new Set([transport]),
        since: this.now(),
      };
      this.peers.set(peerId, record);
      this.emit({
        type: 'peer:join',
        peer: {
          id: peerId,
          transports: [transport],
          rooms: [room],
          since: record.since,
        },
      });
      return;
    }
    if (record.routes.has(key)) return;
    record.routes.set(key, { transport, room });
    record.transports.add(transport);
  }

  private unregisterPeer(peerId: string, transport: MeshTransportKind, room: string): void {
    const record = this.peers.get(peerId);
    if (record === undefined) return;
    const key = `${transport}:${room}`;
    if (!record.routes.delete(key)) return;
    if (record.routes.size > 0) return;
    this.peers.delete(peerId);
    this.emit({ type: 'peer:leave', peerId, transports: [...record.transports] });
  }

  private dispatchMessage(peerId: string, data: unknown): void {
    if (typeof data !== 'string' || data.length === 0 || data.length > this.maxWireChars) {
      return;
    }
    for (const listener of this.messageListeners) {
      try {
        listener({ peerId, data });
      } catch {
        // A routing listener must not break transport callbacks.
      }
    }
  }

  private emit(event: SwarmEvent): void {
    for (const listener of this.eventListeners) {
      try {
        listener(event);
      } catch {
        // UI listeners are isolated from the transport.
      }
    }
  }
}

/* ------------------------------------------------------------------ media */

export interface MediaSwarmOptions {
  readonly transport: OutboundMesh;
  readonly cache?: VideoChunkCache;
  readonly now?: () => number;
  /** Abandon an unanswered chunk request after this long. */
  readonly requestTimeoutMs?: number;
  /** Chunks per MEDIA_REQ. The protocol caps this at six. */
  readonly requestWindow?: number;
  readonly onManifest?: (manifest: MediaManifest, peerId?: string) => void;
  readonly onProgress?: (
    manifest: MediaManifest,
    available: readonly number[],
    total: number,
  ) => void;
  readonly onComplete?: (manifest: MediaManifest, blob: Blob) => void;
  readonly onError?: (message: string, mediaId?: string) => void;
}

interface MediaInflight {
  readonly peerId: string;
  readonly at: number;
  attempts: number;
}

/**
 * Chunk exchange over the same encrypted DataChannels as packet gossip.
 *
 * Peers announce available chunk indices, request small windows, and verify
 * every response against the manifest before storing it. The coordinator is
 * transport-agnostic: `OutboundMesh` supplies send/broadcast/peerIds, so the
 * manual SDP bridge and both signaling strategies all work unchanged.
 */
export class MediaSwarm {
  private readonly transport: OutboundMesh;
  private readonly cache: VideoChunkCache;
  private readonly now: () => number;
  private readonly requestTimeoutMs: number;
  private readonly requestWindow: number;
  private readonly onManifest: ((manifest: MediaManifest, peerId?: string) => void) | undefined;
  private readonly onProgress:
    | ((manifest: MediaManifest, available: readonly number[], total: number) => void)
    | undefined;
  private readonly onComplete: ((manifest: MediaManifest, blob: Blob) => void) | undefined;
  private readonly onError: ((message: string, mediaId?: string) => void) | undefined;

  private readonly manifests = new Map<string, MediaManifest>();
  private readonly peerAvailability = new Map<string, Map<string, Set<number>>>();
  private readonly inflight = new Map<string, Map<number, MediaInflight>>();
  private readonly completed = new Set<string>();
  private readonly refreshing = new Set<string>();
  private readonly announced = new Map<string, string>();
  private readonly timer: ReturnType<typeof setInterval>;

  constructor(options: MediaSwarmOptions) {
    this.transport = options.transport;
    this.cache = options.cache ?? defaultVideoCache;
    this.now = options.now ?? Date.now;
    this.requestTimeoutMs = Math.max(1_000, options.requestTimeoutMs ?? 12_000);
    const window = options.requestWindow ?? 4;
    if (!Number.isSafeInteger(window) || window < 1 || window > MAX_MEDIA_REQUEST_CHUNKS) {
      throw new RangeError(`requestWindow must be between 1 and ${MAX_MEDIA_REQUEST_CHUNKS}`);
    }
    this.requestWindow = window;
    this.onManifest = options.onManifest;
    this.onProgress = options.onProgress;
    this.onComplete = options.onComplete;
    this.onError = options.onError;
    this.timer = setInterval(() => this.tick(), 1_000);
    const maybeUnref = this.timer as unknown as { unref?: () => void };
    maybeUnref.unref?.();
  }

  get manifestCount(): number {
    return this.manifests.size;
  }

  registerManifest(manifest: MediaManifest): void {
    if (!this.manifests.has(manifest.media_id)) {
      this.manifests.set(manifest.media_id, manifest);
      this.onManifest?.(manifest);
    }
  }

  /** Broadcast local availability plus the manifest peers need to verify it. */
  async announce(manifest: MediaManifest): Promise<number[]> {
    this.registerManifest(manifest);
    const available = await availableChunks(manifest, this.cache);
    this.emitProgress(manifest, available);
    if (available.length === 0) return available;
    const signature = available.join(',');
    if (this.announced.get(manifest.media_id) === signature) return available;
    this.announced.set(manifest.media_id, signature);
    const message: MediaHaveMessage = {
      v: 1,
      t: 'MEDIA_HAVE',
      media_id: manifest.media_id,
      available_chunks: available,
      manifest: wireManifest(manifest),
    };
    this.transport.broadcast(encodeWireMessage(message));
    return available;
  }

  async announceAll(manifests: readonly MediaManifest[]): Promise<void> {
    for (const manifest of manifests) {
      await this.announce(manifest);
    }
  }

  onPeerJoin(peerId: string): void {
    if (!this.transport.peerIds().includes(peerId)) return;
    for (const manifest of this.manifests.values()) {
      void this.sendHave(peerId, manifest).then(() => this.requestMissing(manifest));
    }
  }

  onPeerLeave(peerId: string): void {
    for (const peers of this.peerAvailability.values()) {
      peers.delete(peerId);
    }
    for (const [mediaId, pending] of this.inflight) {
      for (const [index, record] of [...pending]) {
        if (record.peerId === peerId) pending.delete(index);
      }
      if (pending.size === 0) this.inflight.delete(mediaId);
    }
  }

  /** Returns true when the message belongs to the media protocol. */
  handleMessage(peerId: string, message: MediaMessage): boolean {
    switch (message.t) {
      case 'MEDIA_HAVE':
        this.absorbHave(peerId, message);
        return true;
      case 'MEDIA_REQ':
        void this.serveRequest(peerId, message);
        return true;
      case 'MEDIA_CHUNK':
        void this.absorbChunk(peerId, message);
        return true;
      default:
        return false;
    }
  }

  /** Kick off a fetch for every registered incomplete manifest. */
  async requestAll(): Promise<void> {
    for (const manifest of this.manifests.values()) {
      await this.requestMissing(manifest);
    }
  }

  /** Register and ask known peers for any missing chunks. */
  request(manifest: MediaManifest): void {
    this.registerManifest(manifest);
    void this.requestMissing(manifest);
  }

  stop(): void {
    clearInterval(this.timer);
    this.inflight.clear();
    this.refreshing.clear();
    this.peerAvailability.clear();
  }

  private absorbHave(peerId: string, message: MediaHaveMessage): void {
    let manifest = this.manifests.get(message.media_id);
    if (message.manifest !== undefined && message.manifest.media_id === message.media_id) {
      manifest = message.manifest;
      this.registerManifest(manifest);
    }
    if (manifest === undefined) {
      this.onError?.('media manifest is not known yet', message.media_id);
      return;
    }

    let peers = this.peerAvailability.get(message.media_id);
    if (peers === undefined) {
      peers = new Map<string, Set<number>>();
      this.peerAvailability.set(message.media_id, peers);
    }
    const valid = message.available_chunks.filter(
      (index) => index >= 0 && index < manifest.total_chunks,
    );
    peers.set(peerId, new Set(valid));
    void this.requestMissing(manifest);
  }

  private async absorbChunk(peerId: string, message: MediaChunkMessage): Promise<void> {
    const manifest = this.manifests.get(message.media_id);
    if (manifest === undefined) {
      this.onError?.('received a chunk for an unknown manifest', message.media_id);
      return;
    }
    let bytes: Uint8Array;
    try {
      bytes = decodeBase64(message.data_b64);
    } catch {
      this.onError?.(`malformed chunk ${message.chunk_index} from ${shortPeer(peerId)}`, message.media_id);
      return;
    }
    const stored = await verifyAndStoreChunk(
      manifest,
      message.chunk_index,
      bytes,
      this.cache,
    );
    if (!stored) {
      this.onError?.(
        `chunk ${message.chunk_index} failed SHA-256 verification`,
        message.media_id,
      );
      return;
    }

    const pending = this.inflight.get(manifest.media_id);
    pending?.delete(message.chunk_index);
    if (pending !== undefined && pending.size === 0) this.inflight.delete(manifest.media_id);

    const available = await availableChunks(manifest, this.cache);
    this.emitProgress(manifest, available);
    if (await hasCompleteMedia(manifest, this.cache)) {
      await this.finish(manifest);
      return;
    }
    await this.requestMissing(manifest);
  }

  private async serveRequest(peerId: string, message: MediaReqMessage): Promise<void> {
    const manifest = this.manifests.get(message.media_id);
    for (const index of message.chunk_indices.slice(0, MAX_MEDIA_REQUEST_CHUNKS)) {
      const chunk = await this.cache.get(message.media_id, index);
      if (chunk === null) continue;
      if (
        manifest !== undefined &&
        (index >= manifest.total_chunks ||
          chunk.length > manifest.chunk_size ||
          chunk.length === 0)
      ) {
        continue;
      }
      const reply: MediaChunkMessage = {
        v: 1,
        t: 'MEDIA_CHUNK',
        media_id: message.media_id,
        chunk_index: index,
        data_b64: encodeBase64(chunk),
      };
      const sent = await this.transport.send(peerId, encodeWireMessage(reply));
      if (!sent) return;
    }
  }

  private async requestMissing(manifest: MediaManifest): Promise<void> {
    if (this.completed.has(manifest.media_id) || this.refreshing.has(manifest.media_id)) return;
    this.refreshing.add(manifest.media_id);
    try {
      const available = new Set(await availableChunks(manifest, this.cache));
      if (available.size === manifest.total_chunks) {
        await this.finish(manifest);
        return;
      }
      const peers = this.peerAvailability.get(manifest.media_id);
      if (peers === undefined || peers.size === 0) return;

      let bestPeer: string | null = null;
      let bestMissing: number[] = [];
      for (const [peerId, announced] of peers) {
        if (!this.transport.peerIds().includes(peerId)) continue;
        const missing = [...announced]
          .filter((index) => !available.has(index))
          .sort((a, b) => a - b);
        if (missing.length > bestMissing.length) {
          bestPeer = peerId;
          bestMissing = missing;
        }
      }
      if (bestPeer === null || bestMissing.length === 0) return;

      const pending = this.inflight.get(manifest.media_id) ?? new Map<number, MediaInflight>();
      const now = this.now();
      const batch: number[] = [];
      for (const index of bestMissing) {
        const record = pending.get(index);
        if (record !== undefined && now - record.at < this.requestTimeoutMs) continue;
        batch.push(index);
        pending.set(index, { peerId: bestPeer, at: now, attempts: (record?.attempts ?? 0) + 1 });
        if (batch.length >= this.requestWindow) break;
      }
      if (batch.length === 0) return;
      this.inflight.set(manifest.media_id, pending);

      const request: MediaReqMessage = {
        v: 1,
        t: 'MEDIA_REQ',
        media_id: manifest.media_id,
        chunk_indices: batch,
      };
      const sent = await this.transport.send(bestPeer, encodeWireMessage(request));
      if (!sent) {
        for (const index of batch) pending.delete(index);
        if (pending.size === 0) this.inflight.delete(manifest.media_id);
      }
    } finally {
      this.refreshing.delete(manifest.media_id);
    }
  }

  private async finish(manifest: MediaManifest): Promise<void> {
    if (this.completed.has(manifest.media_id)) return;
    const blob = await assembleVideoBlob(manifest, this.cache);
    if (blob === null) return;
    this.completed.add(manifest.media_id);
    const available = await availableChunks(manifest, this.cache);
    this.emitProgress(manifest, available);
    this.onComplete?.(manifest, blob);
  }

  private async sendHave(peerId: string, manifest: MediaManifest): Promise<void> {
    const available = await availableChunks(manifest, this.cache);
    const message: MediaHaveMessage = {
      v: 1,
      t: 'MEDIA_HAVE',
      media_id: manifest.media_id,
      available_chunks: available,
      manifest: wireManifest(manifest),
    };
    await this.transport.send(peerId, encodeWireMessage(message));
  }

  private emitProgress(manifest: MediaManifest, available: readonly number[]): void {
    this.onProgress?.(manifest, available, manifest.total_chunks);
  }

  private tick(): void {
    const now = this.now();
    for (const [mediaId, pending] of [...this.inflight]) {
      for (const [index, record] of [...pending]) {
        if (now - record.at >= this.requestTimeoutMs) pending.delete(index);
      }
      if (pending.size === 0) this.inflight.delete(mediaId);
    }
    for (const manifest of this.manifests.values()) {
      if (!this.completed.has(manifest.media_id)) void this.requestMissing(manifest);
    }
  }
}

function shortPeer(peerId: string): string {
  return peerId.length > 18 ? `${peerId.slice(0, 10)}…${peerId.slice(-5)}` : peerId;
}

/**
 * Inline bytes are a carrier payload, not wire data. Peers fetch and verify
 * chunks instead, so announcements stay small even for a 1.5 MB clip.
 */
function wireManifest(manifest: MediaManifest): MediaManifest {
  if (manifest.inline_data_b64 === undefined) return manifest;
  const { inline_data_b64: _inline, ...rest } = manifest;
  return rest;
}
