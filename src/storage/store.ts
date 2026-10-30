/**
 * SPORE storage: a verified, append-only packet DAG with CRDT merge semantics.
 *
 * Three layers, in order:
 *   1. IndexedDB (`spore_db_v1`) — primary, per-packet records.
 *   2. localStorage — whole-state fallback for origins that block IDB.
 *   3. Embedded quine seed — `<script id="spore-quine-state">` read at boot.
 *
 * Any layer may throw a SecurityError/QuotaExceededError on `file://` or in a
 * locked-down WebView. Every access is guarded; the in-memory store is always
 * available and never depends on persistence succeeding.
 *
 * Convergence: packets are a grow-only set keyed by SHA-256 id. Eviction is
 * deterministic — lowest trust score, then lowest PoW bits, then oldest
 * timestamp, then lexicographic id — and evicted ids become tombstones so a
 * re-merge cannot resurrect them.
 */

import { isHex, utf8ByteLength } from '../crypto/encoding';
import { verifyPacket, type PacketFailureReason, type SporePacket } from '../crypto/packet';
import { decodeQuineState, readQuineStateFromDocument } from '../quine/state';

export const DB_NAME = 'spore_db_v1';
export const DB_VERSION = 1;
export const LS_KEY = 'spore_db_v1_state';

const PACKETS_STORE = 'packets';
const META_STORE = 'meta';
const META_KEY = 'state';

export const DEFAULT_MAX_PACKETS = 2_000;
export const DEFAULT_MAX_BYTES = 2_500_000;
export const DEFAULT_MAX_TOMBSTONES = 4_096;
export const DEFAULT_AUTO_FLUSH_MS = 150;
export const DEFAULT_TRUST_SCORE = 0.1;

export type StorageBackend = 'indexeddb' | 'localstorage' | 'memory';

export interface PersistedSporeState {
  readonly v: 1;
  readonly packets: SporePacket[];
  readonly evicted: string[];
  readonly updated_at: number;
}

export interface SporeStoreOptions {
  maxPackets?: number;
  maxBytes?: number;
  maxTombstones?: number;
  /** Reject packets below this PoW at ingress. Default 0 (crypto only). */
  minPowBits?: number;
  /** Injected Web-of-Trust scorer used by deterministic eviction. */
  trustScore?: (pubkey: string) => number;
  /**
   * Ingress gate applied after cryptographic verification. The UI supplies a
   * mute check here so packets from muted authors never enter the store.
   */
  admit?: (packet: SporePacket) => boolean;
  /** Milliseconds to debounce persistence. 0 disables automatic flushes. */
  autoFlushMs?: number;
  /** Explicit seed JSON. `undefined` reads the DOM; `null` disables the seed. */
  seedJson?: string | null;
  document?: Document | null;
  now?: () => number;
}

export interface AppendResult {
  readonly accepted: boolean;
  readonly added: boolean;
  readonly evicted: number;
  readonly reason?: 'duplicate' | 'tombstoned' | 'muted' | PacketFailureReason;
  readonly detail?: string;
}

export interface MergeReport {
  readonly received: number;
  readonly added: number;
  readonly duplicates: number;
  readonly rejected: number;
  readonly tombstoned: number;
  readonly muted: number;
  readonly evicted: number;
}

export interface StoreLoadReport {
  readonly backend: StorageBackend;
  readonly seed: number;
  readonly indexeddb: number;
  readonly localstorage: number;
  readonly rejected: number;
  readonly tombstoned: number;
  readonly muted: number;
  readonly evicted: number;
  readonly persisted: boolean;
  readonly errors: readonly string[];
}

export interface StoreStatus {
  readonly backend: StorageBackend;
  readonly packets: number;
  readonly bytes: number;
  readonly tombstones: number;
  readonly seedPackets: number;
  readonly pending: boolean;
  readonly degraded: boolean;
}

type StoreListener = (store: SporeStore) => void;

type IngestOutcome =
  | { readonly status: 'added'; readonly packet: SporePacket }
  | { readonly status: 'duplicate' }
  | { readonly status: 'tombstoned' }
  | { readonly status: 'muted' }
  | {
      readonly status: 'invalid';
      readonly reason: PacketFailureReason;
      readonly detail: string;
    };

interface PendingBatch {
  readonly upserts: SporePacket[];
  readonly deletes: string[];
  readonly tombstones: string[];
  readonly updatedAt: number;
}

interface ReadState {
  readonly packets: unknown[];
  readonly evicted: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function idOrder(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function packetBytes(packet: SporePacket): number {
  return utf8ByteLength(JSON.stringify(packet));
}

function errorText(error: unknown): string {
  if (error instanceof Error) return error.message;
  return String(error);
}

function getLocalStorage(): Storage | null {
  try {
    return typeof localStorage === 'undefined' ? null : localStorage;
  } catch {
    return null;
  }
}

function parsePersisted(raw: string): ReadState {
  if (raw.length > DEFAULT_MAX_BYTES * 4) {
    throw new Error('Persisted state is implausibly large');
  }
  const parsed: unknown = JSON.parse(raw);
  if (!isRecord(parsed)) throw new Error('Persisted state must be an object');
  if (parsed['v'] !== 1) throw new Error('Unsupported persisted state version');
  const packets = parsed['packets'];
  if (!Array.isArray(packets)) throw new Error('Persisted packets must be an array');
  const evictedRaw = parsed['evicted'];
  const evicted: string[] = [];
  if (evictedRaw !== undefined) {
    if (!Array.isArray(evictedRaw)) throw new Error('Persisted evictions must be an array');
    for (const id of evictedRaw) {
      if (isHex(id, 32)) evicted.push(id.toLowerCase());
    }
  }
  return { packets, evicted };
}

function readLocalStorageState(): { state: ReadState | null; error: string | null } {
  const storage = getLocalStorage();
  if (storage === null) return { state: null, error: null };
  try {
    const raw = storage.getItem(LS_KEY);
    if (raw === null || raw.length === 0) return { state: null, error: null };
    return { state: parsePersisted(raw), error: null };
  } catch (error) {
    return { state: null, error: `localStorage read failed: ${errorText(error)}` };
  }
}

function writeLocalStorageState(snapshot: PersistedSporeState): { ok: boolean; error: string | null } {
  const storage = getLocalStorage();
  if (storage === null) return { ok: false, error: 'localStorage unavailable' };
  try {
    storage.setItem(LS_KEY, JSON.stringify(snapshot));
    return { ok: true, error: null };
  } catch (error) {
    return { ok: false, error: `localStorage write failed: ${errorText(error)}` };
  }
}

function openDatabase(): Promise<IDBDatabase> {
  return new Promise<IDBDatabase>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    const finish = (fn: () => void): void => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      fn();
    };

    let request: IDBOpenDBRequest;
    try {
      if (typeof indexedDB === 'undefined') throw new Error('IndexedDB unavailable');
      request = indexedDB.open(DB_NAME, DB_VERSION);
    } catch (error) {
      reject(error);
      return;
    }

    timer = setTimeout(() => {
      if (settled) return;
      settled = true;
      reject(new Error('IndexedDB open timed out'));
    }, 2_500);

    request.onupgradeneeded = () => {
      const db = request.result;
      if (!db.objectStoreNames.contains(PACKETS_STORE)) {
        db.createObjectStore(PACKETS_STORE, { keyPath: 'id' });
      }
      if (!db.objectStoreNames.contains(META_STORE)) {
        db.createObjectStore(META_STORE, { keyPath: 'key' });
      }
    };
    request.onsuccess = () => {
      const db = request.result;
      if (settled) {
        db.close();
        return;
      }
      finish(() => resolve(db));
    };
    request.onerror = () => {
      finish(() => reject(request.error ?? new Error('IndexedDB open failed')));
    };
    request.onblocked = () => {
      finish(() => reject(new Error('IndexedDB open blocked by another tab')));
    };
  });
}

function transactionDone(tx: IDBTransaction): Promise<void> {
  return new Promise<void>((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error ?? new Error('IndexedDB transaction failed'));
    tx.onabort = () => reject(tx.error ?? new Error('IndexedDB transaction aborted'));
  });
}

async function readIndexedDb(db: IDBDatabase): Promise<ReadState> {
  const tx = db.transaction([PACKETS_STORE, META_STORE], 'readonly');
  const done = transactionDone(tx);
  const packetsRequest = tx.objectStore(PACKETS_STORE).getAll();
  const metaRequest = tx.objectStore(META_STORE).get(META_KEY);
  await done;

  const packets: unknown[] = packetsRequest.result;
  const meta = metaRequest.result as unknown;
  const evicted: string[] = [];
  if (isRecord(meta) && Array.isArray(meta['evicted'])) {
    for (const id of meta['evicted']) {
      if (isHex(id, 32)) evicted.push(id.toLowerCase());
    }
  }
  return { packets, evicted };
}

async function writeIndexedDb(db: IDBDatabase, batch: PendingBatch): Promise<void> {
  const tx = db.transaction([PACKETS_STORE, META_STORE], 'readwrite');
  const done = transactionDone(tx);
  const packetsStore = tx.objectStore(PACKETS_STORE);
  for (const packet of batch.upserts) packetsStore.put(packet);
  for (const id of batch.deletes) packetsStore.delete(id);
  tx.objectStore(META_STORE).put({
    key: META_KEY,
    v: 1,
    evicted: batch.tombstones,
    updated_at: batch.updatedAt,
  });
  await done;
}

export class SporeStore {
  private readonly packets = new Map<string, SporePacket>();
  private readonly tombstones = new Set<string>();
  private readonly tombstoneOrder: string[] = [];
  private readonly seedIdSet = new Set<string>();
  private readonly listeners = new Set<StoreListener>();
  private readonly pendingUpserts = new Map<string, SporePacket>();
  private readonly pendingDeletes = new Set<string>();

  private readonly maxPackets: number;
  private readonly maxBytes: number;
  private readonly maxTombstones: number;
  private readonly minPowBits: number;
  private readonly autoFlushMs: number;
  private readonly seedJson: string | null | undefined;
  private readonly doc: Document | null | undefined;
  private readonly now: () => number;
  private readonly admitFn: (packet: SporePacket) => boolean;

  private trustScoreFn: (pubkey: string) => number;
  private byteSize = 0;
  private backend: StorageBackend = 'memory';
  private db: IDBDatabase | null = null;
  private dbPromise: Promise<IDBDatabase> | null = null;
  private idbUnavailable = false;
  private flushTimer: ReturnType<typeof setTimeout> | null = null;
  private flushPromise: Promise<boolean> | null = null;
  private mutationSeq = 0;
  private metaDirty = false;
  private lastError: string | null = null;

  constructor(options: SporeStoreOptions = {}) {
    this.maxPackets = options.maxPackets ?? DEFAULT_MAX_PACKETS;
    this.maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
    this.maxTombstones = options.maxTombstones ?? DEFAULT_MAX_TOMBSTONES;
    this.minPowBits = options.minPowBits ?? 0;
    this.autoFlushMs = options.autoFlushMs ?? DEFAULT_AUTO_FLUSH_MS;
    this.seedJson = options.seedJson;
    this.doc = options.document;
    this.now = options.now ?? Date.now;
    this.trustScoreFn = options.trustScore ?? (() => DEFAULT_TRUST_SCORE);
    this.admitFn = options.admit ?? (() => true);

    if (!Number.isSafeInteger(this.maxPackets) || this.maxPackets < 1) {
      throw new RangeError('maxPackets must be a positive integer');
    }
    if (!Number.isSafeInteger(this.maxBytes) || this.maxBytes < 1_024) {
      throw new RangeError('maxBytes must be an integer of at least 1024');
    }
    if (!Number.isSafeInteger(this.maxTombstones) || this.maxTombstones < 1) {
      throw new RangeError('maxTombstones must be a positive integer');
    }
    if (!Number.isSafeInteger(this.minPowBits) || this.minPowBits < 0 || this.minPowBits > 64) {
      throw new RangeError('minPowBits must be between 0 and 64');
    }
    if (!Number.isSafeInteger(this.autoFlushMs) || this.autoFlushMs < 0) {
      throw new RangeError('autoFlushMs must be a non-negative integer');
    }
  }

  get size(): number {
    return this.packets.size;
  }

  get bytes(): number {
    return this.byteSize;
  }

  get seedPackets(): number {
    return this.seedIdSet.size;
  }

  get backendName(): StorageBackend {
    return this.backend;
  }

  get persistenceError(): string | null {
    return this.lastError;
  }

  get status(): StoreStatus {
    return {
      backend: this.backend,
      packets: this.packets.size,
      bytes: this.byteSize,
      tombstones: this.tombstones.size,
      seedPackets: this.seedIdSet.size,
      pending: this.hasPending(),
      degraded: this.backend === 'memory' && this.packets.size > 0,
    };
  }

  isSeedPacket(id: string): boolean {
    return this.seedIdSet.has(id);
  }

  get(id: string): SporePacket | undefined {
    return this.packets.get(id);
  }

  /** Deterministic chronological snapshot (content-addressed, immutable). */
  packetsSnapshot(): SporePacket[] {
    return [...this.packets.values()].sort(
      (a, b) => a.created_at - b.created_at || idOrder(a.id, b.id),
    );
  }

  /** DAG children of a packet (replies). */
  childrenOf(id: string): SporePacket[] {
    return this.packetsSnapshot().filter((packet) => packet.reply_to === id);
  }

  /** DAG parents of a packet (at most one in SPORE v1). */
  parentsOf(packet: SporePacket): SporePacket[] {
    const parentId = packet.reply_to;
    if (parentId === undefined) return [];
    const parent = this.packets.get(parentId);
    return parent === undefined ? [] : [parent];
  }

  tips(): SporePacket[] {
    const parentIds = new Set<string>();
    for (const packet of this.packets.values()) {
      if (packet.reply_to !== undefined) parentIds.add(packet.reply_to);
    }
    return this.packetsSnapshot().filter((packet) => !parentIds.has(packet.id));
  }

  setTrustScorer(scorer: (pubkey: string) => number): void {
    this.trustScoreFn = scorer;
  }

  subscribe(listener: StoreListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  private scoreOf(pubkey: string): number {
    try {
      const score = this.trustScoreFn(pubkey);
      return Number.isFinite(score) ? Math.min(Math.max(score, 0), 1) : DEFAULT_TRUST_SCORE;
    } catch {
      return DEFAULT_TRUST_SCORE;
    }
  }

  private verifyOptions(): { minPowBits?: number } {
    return this.minPowBits > 0 ? { minPowBits: this.minPowBits } : {};
  }

  private ingest(candidate: unknown): IngestOutcome {
    const verified = verifyPacket(candidate, this.verifyOptions());
    if (!verified.ok) {
      return { status: 'invalid', reason: verified.reason, detail: verified.detail };
    }
    const packet = verified.packet;
    if (this.tombstones.has(packet.id)) return { status: 'tombstoned' };
    if (this.packets.has(packet.id)) return { status: 'duplicate' };
    try {
      if (!this.admitFn(packet)) return { status: 'muted' };
    } catch {
      // A broken trust predicate must fail closed for muted policy.
      return { status: 'muted' };
    }

    const stored: SporePacket = Object.freeze({
      ...packet,
      ...(packet.media_cid !== undefined ? { media_cid: packet.media_cid } : {}),
      ...(packet.reply_to !== undefined ? { reply_to: packet.reply_to } : {}),
    });
    this.packets.set(stored.id, stored);
    this.byteSize += packetBytes(stored);
    this.pendingUpserts.set(stored.id, stored);
    this.pendingDeletes.delete(stored.id);
    return { status: 'added', packet: stored };
  }

  append(candidate: unknown): AppendResult {
    const outcome = this.ingest(candidate);
    const evicted = this.enforceLimits();

    if (outcome.status === 'invalid') {
      return {
        accepted: false,
        added: false,
        evicted,
        reason: outcome.reason,
        detail: outcome.detail,
      };
    }
    if (outcome.status === 'tombstoned') {
      return { accepted: false, added: false, evicted, reason: 'tombstoned' };
    }
    if (outcome.status === 'muted') {
      return { accepted: false, added: false, evicted, reason: 'muted' };
    }
    if (outcome.status === 'duplicate') {
      return { accepted: true, added: false, evicted, reason: 'duplicate' };
    }

    this.afterMutation();
    return { accepted: true, added: true, evicted };
  }

  merge(candidates: Iterable<unknown>): MergeReport {
    let received = 0;
    let added = 0;
    let duplicates = 0;
    let rejected = 0;
    let tombstoned = 0;
    let muted = 0;

    for (const candidate of candidates) {
      received += 1;
      const outcome = this.ingest(candidate);
      switch (outcome.status) {
        case 'added':
          added += 1;
          break;
        case 'duplicate':
          duplicates += 1;
          break;
        case 'tombstoned':
          tombstoned += 1;
          break;
        case 'muted':
          muted += 1;
          break;
        case 'invalid':
          rejected += 1;
          break;
      }
    }

    const evicted = this.enforceLimits();
    if (added > 0 || evicted > 0) this.afterMutation();

    return { received, added, duplicates, rejected, tombstoned, muted, evicted };
  }

  rebalance(): number {
    const evicted = this.enforceLimits();
    if (evicted > 0) this.afterMutation();
    return evicted;
  }

  private enforceLimits(): number {
    if (this.packets.size <= this.maxPackets && this.byteSize <= this.maxBytes) return 0;

    const candidates = [...this.packets.values()].sort((a, b) => {
      const scoreDelta = this.scoreOf(a.pubkey) - this.scoreOf(b.pubkey);
      if (scoreDelta !== 0) return scoreDelta;
      if (a.pow_bits !== b.pow_bits) return a.pow_bits - b.pow_bits;
      if (a.created_at !== b.created_at) return a.created_at - b.created_at;
      return idOrder(a.id, b.id);
    });

    let evicted = 0;
    for (const packet of candidates) {
      if (this.packets.size <= this.maxPackets && this.byteSize <= this.maxBytes) break;
      this.packets.delete(packet.id);
      this.byteSize -= packetBytes(packet);
      this.pendingUpserts.delete(packet.id);
      this.pendingDeletes.add(packet.id);
      this.rememberTombstone(packet.id);
      evicted += 1;
    }
    return evicted;
  }

  private rememberTombstone(id: string): void {
    if (this.tombstones.has(id)) return;
    this.tombstones.add(id);
    this.tombstoneOrder.push(id);
    while (this.tombstoneOrder.length > this.maxTombstones) {
      const oldest = this.tombstoneOrder.shift();
      if (oldest !== undefined) this.tombstones.delete(oldest);
    }
    this.metaDirty = true;
  }

  private afterMutation(): void {
    this.mutationSeq += 1;
    this.notify();
    this.scheduleFlush();
  }

  private notify(): void {
    for (const listener of this.listeners) {
      try {
        listener(this);
      } catch {
        // A broken UI listener must not break storage.
      }
    }
  }

  private hasPending(): boolean {
    return this.pendingUpserts.size > 0 || this.pendingDeletes.size > 0 || this.metaDirty;
  }

  private snapshot(): PersistedSporeState {
    return {
      v: 1,
      packets: this.packetsSnapshot(),
      evicted: [...this.tombstones].sort(idOrder),
      updated_at: this.now(),
    };
  }

  private scheduleFlush(): void {
    if (this.autoFlushMs <= 0 || this.flushTimer !== null) return;
    const timer = setTimeout(() => {
      this.flushTimer = null;
      void this.flush();
    }, this.autoFlushMs);
    const maybeUnref = timer as unknown as { unref?: () => void };
    maybeUnref.unref?.();
    this.flushTimer = timer;
  }

  private cancelFlushTimer(): void {
    if (this.flushTimer === null) return;
    clearTimeout(this.flushTimer);
    this.flushTimer = null;
  }

  private getDb(): Promise<IDBDatabase> {
    if (this.db !== null) return Promise.resolve(this.db);
    if (this.idbUnavailable) return Promise.reject(new Error('IndexedDB unavailable'));
    if (this.dbPromise === null) {
      this.dbPromise = openDatabase()
        .then((db) => {
          this.db = db;
          return db;
        })
        .catch((error: unknown) => {
          this.idbUnavailable = true;
          this.dbPromise = null;
          throw error;
        });
    }
    return this.dbPromise;
  }

  private disableIdb(error: unknown): void {
    this.lastError = errorText(error);
    this.idbUnavailable = true;
    this.dbPromise = null;
    if (this.db !== null) {
      try {
        this.db.close();
      } catch {
        // closed already
      }
      this.db = null;
    }
  }

  private async readIdbLayer(): Promise<ReadState | null> {
    try {
      const db = await this.getDb();
      return await readIndexedDb(db);
    } catch (error) {
      if (!this.idbUnavailable) this.disableIdb(error);
      return null;
    }
  }

  private async writeIdbLayer(batch: PendingBatch): Promise<boolean> {
    try {
      const db = await this.getDb();
      await writeIndexedDb(db, batch);
      return true;
    } catch (error) {
      this.disableIdb(error);
      return false;
    }
  }

  private async probeBackend(): Promise<StorageBackend> {
    try {
      await this.getDb();
      return 'indexeddb';
    } catch {
      // fall through
    }
    return getLocalStorage() === null ? 'memory' : 'localstorage';
  }

  private markAllDirty(): void {
    for (const packet of this.packets.values()) this.pendingUpserts.set(packet.id, packet);
    this.metaDirty = this.tombstones.size > 0;
    this.mutationSeq += 1;
  }

  async load(): Promise<StoreLoadReport> {
    const errors: string[] = [];
    let rejected = 0;
    let tombstoned = 0;
    let muted = 0;

    let seedState: { packets: SporePacket[]; rejected: number } | null = null;
    try {
      const raw =
        this.seedJson !== undefined
          ? this.seedJson
          : readQuineStateFromDocument(this.doc);
      if (raw !== null && raw.length > 0) {
        const decoded = decodeQuineState(raw);
        seedState = { packets: decoded.packets, rejected: decoded.rejected };
        rejected += decoded.rejected;
      }
    } catch (error) {
      errors.push(`seed rejected: ${errorText(error)}`);
    }

    const localStorageRead = readLocalStorageState();
    if (localStorageRead.error !== null) errors.push(localStorageRead.error);

    const [idbState, lsState] = await Promise.all([
      this.readIdbLayer(),
      Promise.resolve(localStorageRead.state),
    ]);

    for (const evictedId of [...(idbState?.evicted ?? []), ...(lsState?.evicted ?? [])]) {
      this.rememberTombstone(evictedId);
    }

    const seedIds = new Set<string>();
    if (seedState !== null) {
      for (const packet of seedState.packets) {
        const outcome = this.ingest(packet);
        if (outcome.status === 'added' || outcome.status === 'duplicate') {
          seedIds.add(packet.id);
        } else if (outcome.status === 'invalid') {
          rejected += 1;
        } else if (outcome.status === 'muted') {
          muted += 1;
        } else {
          tombstoned += 1;
        }
      }
    }

    const ingestLayer = (state: ReadState | null): number => {
      if (state === null) return 0;
      for (const packet of state.packets) {
        const outcome = this.ingest(packet);
        if (outcome.status === 'invalid') rejected += 1;
        else if (outcome.status === 'tombstoned') tombstoned += 1;
        else if (outcome.status === 'muted') muted += 1;
      }
      return state.packets.length;
    };

    const lsCount = ingestLayer(lsState);
    const idbCount = ingestLayer(idbState);

    const evicted = this.enforceLimits();

    for (const id of seedIds) {
      if (this.packets.has(id)) this.seedIdSet.add(id);
    }
    if (this.packets.size === 0 && !this.hasPending()) {
      this.backend = await this.probeBackend();
    } else {
      this.markAllDirty();
    }

    const persisted = await this.flush();
    const report: StoreLoadReport = {
      backend: this.backend,
      seed: seedIds.size,
      indexeddb: idbCount,
      localstorage: lsCount,
      rejected,
      tombstoned,
      muted,
      evicted,
      persisted,
      errors,
    };

    this.notify();
    return report;
  }

  async flush(): Promise<boolean> {
    if (this.flushPromise !== null) return this.flushPromise;
    this.cancelFlushTimer();
    this.flushPromise = this.doFlush().finally(() => {
      this.flushPromise = null;
    });
    return this.flushPromise;
  }

  private async doFlush(): Promise<boolean> {
    if (!this.hasPending()) {
      if (this.backend === 'memory') this.backend = await this.probeBackend();
      return true;
    }

    const sequence = this.mutationSeq;
    const batch: PendingBatch = {
      upserts: [...this.pendingUpserts.values()],
      deletes: [...this.pendingDeletes],
      tombstones: [...this.tombstones].sort(idOrder),
      updatedAt: this.now(),
    };

    if (await this.writeIdbLayer(batch)) {
      this.backend = 'indexeddb';
      this.afterPersist(sequence);
      return true;
    }

    const snapshot = this.snapshot();
    const lsResult = writeLocalStorageState(snapshot);
    if (lsResult.ok) {
      this.backend = 'localstorage';
      this.afterPersist(sequence);
      return true;
    }
    if (lsResult.error !== null) this.lastError = lsResult.error;
    this.backend = 'memory';
    return false;
  }

  private afterPersist(sequence: number): void {
    if (sequence !== this.mutationSeq) {
      this.scheduleFlush();
      return;
    }
    this.pendingUpserts.clear();
    this.pendingDeletes.clear();
    this.metaDirty = false;
  }

  /** Compact the in-memory set immediately (used after trust graph updates). */
  compact(): number {
    return this.rebalance();
  }
}
