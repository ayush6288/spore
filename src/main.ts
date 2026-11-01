import './styles.css';
import {
  decryptIdentity,
  encryptIdentity,
  fingerprintOf,
  generateIdentity,
  isValidPublicKey,
  parseKeyBackup,
  serializeKeyBackup,
  type EncryptedKeyBackup,
} from './crypto/identity';
import {
  sealPacket,
  verifyPacket,
  type MediaManifest,
  type PacketVerificationResult,
  type SporePacket,
} from './crypto/packet';
import type { MiningProgress } from './crypto/pow';
import {
  assembleVideoBlob,
  availableChunks,
  importInlineMedia,
  ingestVideoFile,
  type VideoSlice,
} from './media/videoSwarm';
import { DandelionRouter, type PublishRoute } from './net/dandelion';
import { GossipEngine } from './net/gossip';
import { isMediaMessage, parseWireMessage, type WireMessage } from './net/protocol';
import { MediaSwarm, Swarm, parseTopicChannels } from './net/swarm';
import { Telemetry, type TelemetryEvent, type TelemetryEventName } from './net/telemetry';
import { transportLabel } from './net/transport';
import { exportSporeQuine } from './quine/compiler';
import {
  MAX_RECEIPT_SOURCE_BYTES,
  createHydraReceipt,
  hashMediaBytes,
  hashMediaText,
  normalizeSocialUrl,
  parseHydraReceipt,
  platformLabel,
  receiptProofText,
  verifyHydraReceipt,
  type HydraReceiptContent,
  type ReceiptSource,
} from './receipts/hydraReceipt';
import { decodePacketsFromStegoPng, encodePacketsToStegoPng } from './stego/pngCarrier';
import {
  SporeStore,
  type StorageBackend,
  type StoreLoadReport,
} from './storage/store';
import {
  TrustGraph,
  encodeTrustContent,
  type TrustAction,
  type TrustRelation,
} from './trust/wot';

const TRUST_POW_BITS = 12;
const HIGH_POW_BITS = 16;
const FEED_LIMIT = 100;
const QUINE_PACKET_LIMIT = 200;
const LOG_LIMIT = 240;

const BACKEND_LABELS: Record<StorageBackend, string> = {
  indexeddb: 'IndexedDB',
  localstorage: 'localStorage',
  memory: 'memory only',
};

const RELATION_LABELS: Record<TrustRelation, string> = {
  self: 'self',
  direct: 'following',
  'second-hop': 'vouched',
  unknown: 'unknown',
  muted: 'muted',
};

const TIER_LABELS: Record<TrustRelation, string> = {
  self: 'SELF',
  direct: '1-HOP',
  'second-hop': '2-HOP',
  unknown: 'POW-ONLY',
  muted: 'MUTED',
};

type Tone = 'idle' | 'ok' | 'error' | 'busy';
type FeedFilter = 'all' | '2hop' | 'pow';
type ComposerMode = 'post' | 'receipt';
type LogTone = 'stem' | 'fluff' | 'sync' | 'verified' | 'drop' | 'peer';

interface LogEntry {
  readonly at: number;
  readonly name: string;
  readonly label: string;
  readonly detail: string;
  readonly tone: LogTone;
}

const LOG_LABELS: Record<TelemetryEventName, string> = {
  'peer:join': 'PEER',
  'peer:leave': 'PEER',
  'pkt:stem': 'STEM',
  'pkt:fluff': 'FLUFF',
  'pkt:drop': 'DROP',
  'sync:complete': 'SYNC',
};

const LOG_TONES: Record<TelemetryEventName, LogTone> = {
  'peer:join': 'peer',
  'peer:leave': 'peer',
  'pkt:stem': 'stem',
  'pkt:fluff': 'fluff',
  'pkt:drop': 'drop',
  'sync:complete': 'sync',
};

interface GuideStep {
  readonly kicker: string;
  readonly title: string;
  readonly body: readonly string[];
  readonly target?: string;
}

const GUIDE_STEPS: readonly GuideStep[] = [
  {
    kicker: 'STEP 1 · THE BASICS',
    title: 'One file. No origin server.',
    body: [
      'SPORE is a publishing client that lives entirely in this HTML document. It boots offline, makes zero network requests until you ask, and can be copied by email, USB, or any messenger.',
      'Everything you publish is signed locally with a secp256k1 key and sealed with Hashcash proof of work. Readers verify the signatures and hashes themselves.',
    ],
    target: '.brand-block',
  },
  {
    kicker: 'STEP 2 · IDENTITY',
    title: 'Your key is ephemeral until you back it up.',
    body: [
      'The fingerprint below is derived from a fresh key generated in this tab. It is not saved across reloads.',
      'Open key vault, enter a passphrase, and press encrypt key to create an encrypted backup. To restore, press restore…, paste the JSON, and press decrypt & adopt key. The private key is never displayed raw.',
    ],
    target: '#fingerprint',
  },
  {
    kicker: 'STEP 3 · DISCOVERY',
    title: 'Join only when you want the live mesh.',
    body: [
      'Type a channel or topic, then press join. SPORE uses BitTorrent WebSocket trackers and Nostr relays for signaling, and WebRTC DataChannels for peer traffic.',
      'If public signaling is blocked, open the WebRTC peer bridge and exchange a spore-peer:// invite over any messenger. Press leave to stop signaling; direct peers stay connected.',
    ],
    target: '.channel-switcher',
  },
  {
    kicker: 'STEP 4 · PUBLISH',
    title: 'Write, choose work, seal.',
    body: [
      'Write in the composer, pick 8–20 proof-of-work bits, and press mine & seal post. The packet is mined, signed, verified, stored, and routed through the Dandelion++ stem.',
      'Keep Dandelion++ Stem Routing checked for source obfuscation, or uncheck it to broadcast directly. Mining can be cancelled without freezing the tab.',
    ],
    target: '#content',
  },
  {
    kicker: 'STEP 5 · VIDEO',
    title: 'Attach a Reel and seed it as a swarm.',
    body: [
      'Press Import Reel Video. SPORE slices the file into 64 KiB chunks, hashes each chunk and the complete binary with SHA-256, and stores them in IndexedDB plus an in-memory fallback.',
      'Small clips up to 1.5 MB embed inline, so a stego PNG or Quine can play them with zero peers online. Larger clips are fetched from peers in 4–6 chunk windows and verified before assembly.',
    ],
    target: '#import-video',
  },
  {
    kicker: 'STEP 6 · THE FEED',
    title: 'Watch packets and video arrive.',
    body: [
      'The Field Feed admits verified packets by trust, work, and recency. Media posts show a player once every chunk is local and hash-verified.',
      'Unknown authors need a 16-bit work floor. Trust is local: follow, vouch, or mute an author, and choose All Verified, 2-Hop Trusted Only, or High PoW Only.',
    ],
    target: '.feed-panel',
  },
  {
    kicker: 'STEP 7 · OFFLINE CARRIERS',
    title: 'Carry the feed across a blackout.',
    body: [
      'Export a self-replicating Quine to embed the app plus up to 200 verified packets in one HTML file. Press Pack into Stego PNG on any post to render a lossless RGB LSB carrier.',
      'Both formats work from file:// with no server. They are public, not encrypted: anyone who has the file can read it.',
    ],
    target: '#export-quine',
  },
  {
    kicker: 'STEP 8 · COMMAND CONSOLE',
    title: 'One input for the common actions.',
    body: [
      'The console accepts /help, /join, /leave, /post, /seal, /video, /import, /export, /filter, /receipt, /vault, /bridge, /diagnostics, /status, and /guide.',
      'Use the arrow keys to recall commands. Every original button remains available; the diagnostics toggle hides the protocol trace without deleting it from the DOM.',
    ],
    target: '#command-input',
  },
  {
    kicker: 'STEP 9 · READY',
    title: 'Publish, mirror, repeat.',
    body: [
      'SPORE is a prototype, not an audited security product. Packets are public, Dandelion++-style routing is source obfuscation rather than anonymity, and direct WebRTC peers may learn your IP address.',
      'Back up your key, verify packets rather than screenshots, and keep an offline copy of the HTML you trust.',
    ],
    target: '.site-footer',
  },
];

const numberFormat = new Intl.NumberFormat('en-US');

function byId<T extends HTMLElement>(id: string): T {
  const node = document.getElementById(id);
  if (node === null) throw new Error(`Missing element #${id}`);
  return node as T;
}

function errorMessage(error: unknown): string {
  if (error instanceof Error && error.message.length > 0) return error.message;
  return String(error);
}

function setStatus(node: HTMLElement, text: string, tone: Tone = 'idle'): void {
  node.textContent = text;
  if (tone === 'idle') {
    delete node.dataset['tone'];
  } else {
    node.dataset['tone'] = tone;
  }
}

function formatCount(value: number): string {
  return numberFormat.format(Math.round(value));
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MiB`;
}

function makeElement<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  className?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const element = document.createElement(tag);
  if (className !== undefined) element.className = className;
  if (text !== undefined) element.textContent = text;
  return element;
}

function formatTimestamp(seconds: number): string {
  const date = new Date(seconds * 1000);
  if (Number.isNaN(date.getTime())) return 'invalid time';
  return `${date.toISOString().slice(0, 16).replace('T', ' ')}Z`;
}

function nextFrame(): Promise<void> {
  return new Promise<void>((resolve) => {
    if (typeof requestAnimationFrame === 'function') {
      requestAnimationFrame(() => resolve());
    } else {
      setTimeout(resolve, 0);
    }
  });
}

async function copyText(text: string, status: HTMLElement): Promise<void> {
  try {
    if (navigator.clipboard === undefined) throw new Error('Clipboard API unavailable');
    await navigator.clipboard.writeText(text);
    setStatus(status, 'copied to clipboard', 'ok');
    return;
  } catch {
    // file:// and older WebViews often block the async clipboard; fall back.
  }

  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '-2000px';
  document.body.append(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand('copy');
  } catch {
    copied = false;
  }
  area.remove();
  setStatus(
    status,
    copied ? 'copied to clipboard' : 'copy failed — select and copy manually',
    copied ? 'ok' : 'error',
  );
}

function downloadBlob(blob: Blob, fileName: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  document.body.append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

function openDialog(dialog: HTMLDialogElement): void {
  if (dialog.open) return;
  if (typeof dialog.showModal === 'function') {
    dialog.showModal();
  } else {
    dialog.setAttribute('open', '');
  }
}

function closeDialog(dialog: HTMLDialogElement): void {
  if (!dialog.open) return;
  if (typeof dialog.close === 'function') {
    dialog.close();
  } else {
    dialog.removeAttribute('open');
  }
}

function boot(): void {
  /* --------------------------------------------------------------- elements */

  const fingerprintEl = byId<HTMLElement>('fingerprint');
  const pubkeyEl = byId<HTMLElement>('pubkey');
  const copyPubkeyButton = byId<HTMLButtonElement>('copy-pubkey');
  const rotateButton = byId<HTMLButtonElement>('rotate');
  const identityStatus = byId<HTMLElement>('identity-status');
  const openIdentityButton = byId<HTMLButtonElement>('open-identity');
  const closeIdentityButton = byId<HTMLButtonElement>('close-identity');
  const identityModal = byId<HTMLDialogElement>('identity-modal');

  const backupPass = byId<HTMLInputElement>('backup-pass');
  const backupJson = byId<HTMLTextAreaElement>('backup-json');
  const encryptButton = byId<HTMLButtonElement>('encrypt-key');
  const restoreToggle = byId<HTMLButtonElement>('restore-toggle');
  const restoreBox = byId<HTMLElement>('restore-box');
  const restorePass = byId<HTMLInputElement>('restore-pass');
  const restoreButton = byId<HTMLButtonElement>('restore-key');
  const backupStatus = byId<HTMLElement>('backup-status');

  const trustPubkey = byId<HTMLInputElement>('trust-pubkey');
  const vouchPubkeyButton = byId<HTMLButtonElement>('vouch-pubkey');
  const mutePubkeyButton = byId<HTMLButtonElement>('mute-pubkey');
  const trustStatus = byId<HTMLElement>('trust-status');
  const filterAll = byId<HTMLButtonElement>('filter-all');
  const filter2Hop = byId<HTMLButtonElement>('filter-2hop');
  const filterPow = byId<HTMLButtonElement>('filter-pow');

  const contentEl = byId<HTMLTextAreaElement>('content');
  const modePostButton = byId<HTMLButtonElement>('mode-post');
  const modeReceiptButton = byId<HTMLButtonElement>('mode-receipt');
  const postFields = byId<HTMLElement>('post-fields');
  const receiptFields = byId<HTMLElement>('receipt-fields');
  const receiptUrlInput = byId<HTMLInputElement>('receipt-url');
  const receiptSourceInput = byId<HTMLTextAreaElement>('receipt-source');
  const receiptFileInput = byId<HTMLInputElement>('receipt-file');
  const receiptClearButton = byId<HTMLButtonElement>('receipt-clear');
  const receiptDigestEl = byId<HTMLElement>('receipt-digest');
  const receiptNoteInput = byId<HTMLInputElement>('receipt-note');
  const receiptStatus = byId<HTMLElement>('receipt-status');

  const powSlider = byId<HTMLInputElement>('pow-bits');
  const powOutput = byId<HTMLOutputElement>('pow-output');
  const powRate = byId<HTMLElement>('pow-rate');
  const dandelionToggle = byId<HTMLInputElement>('dandelion-toggle');
  const sealButton = byId<HTMLButtonElement>('seal');
  const cancelButton = byId<HTMLButtonElement>('cancel');
  const progressBar = byId<HTMLElement>('progress-bar');
  const mineStatus = byId<HTMLElement>('mine-status');

  const packetResult = byId<HTMLElement>('packet-result');
  const verdictEl = byId<HTMLElement>('verdict');
  const resultId = byId<HTMLElement>('result-id');
  const resultPow = byId<HTMLElement>('result-pow');
  const resultTime = byId<HTMLElement>('result-time');
  const resultSig = byId<HTMLElement>('result-sig');
  const resultJson = byId<HTMLElement>('result-json');
  const copyPacketButton = byId<HTMLButtonElement>('copy-packet');

  const storeStatus = byId<HTMLElement>('store-status');
  const storageMode = byId<HTMLElement>('storage-mode');
  const exportQuineButton = byId<HTMLButtonElement>('export-quine');
  const importStegoButton = byId<HTMLButtonElement>('import-stego');
  const stegoFileInput = byId<HTMLInputElement>('stego-file');
  const stegoStatus = byId<HTMLElement>('stego-status');
  const feedEl = byId<HTMLElement>('feed');
  const feedCount = byId<HTMLElement>('feed-count');
  const feedStatus = byId<HTMLElement>('feed-status');

  const meshStatus = byId<HTMLElement>('mesh-status');
  const meshSummary = byId<HTMLElement>('mesh-summary');
  const topicsInput = byId<HTMLInputElement>('topics');
  const meshConnectButton = byId<HTMLButtonElement>('mesh-connect');
  const meshDisconnectButton = byId<HTMLButtonElement>('mesh-disconnect');
  const meshNote = byId<HTMLElement>('mesh-note');
  const peerCount = byId<HTMLElement>('peer-count');
  const peerList = byId<HTMLElement>('peer-list');
  const nodePill = byId<HTMLElement>('node-pill');
  const nodeStatusText = byId<HTMLElement>('node-status-text');
  const peersStat = byId<HTMLElement>('peers-stat');
  const relaysStat = byId<HTMLElement>('relays-stat');

  const openManualButton = byId<HTMLButtonElement>('open-manual');
  const closeManualButton = byId<HTMLButtonElement>('close-manual');
  const manualBox = byId<HTMLDialogElement>('manual-box');
  const manualCode = byId<HTMLTextAreaElement>('manual-code');
  const manualOfferButton = byId<HTMLButtonElement>('manual-offer');
  const manualAcceptButton = byId<HTMLButtonElement>('manual-accept');
  const manualAnswerButton = byId<HTMLButtonElement>('manual-answer');
  const manualCopyButton = byId<HTMLButtonElement>('manual-copy');
  const manualStatus = byId<HTMLElement>('manual-status');

  const appShell = byId<HTMLElement>('app');
  const commandForm = byId<HTMLFormElement>('command-form');
  const commandInput = byId<HTMLInputElement>('command-input');
  const commandStatus = byId<HTMLElement>('command-status');
  const openGuideButton = byId<HTMLButtonElement>('open-guide');
  const toggleAdvancedButton = byId<HTMLButtonElement>('toggle-advanced');

  const videoFileInput = byId<HTMLInputElement>('video-file');
  const importVideoButton = byId<HTMLButtonElement>('import-video');
  const clearVideoButton = byId<HTMLButtonElement>('clear-video');
  const videoAttachTag = byId<HTMLElement>('video-attach-tag');
  const videoHint = byId<HTMLElement>('video-hint');
  const videoStatus = byId<HTMLElement>('video-status');
  const videoPreview = byId<HTMLVideoElement>('video-preview');

  const guideModal = byId<HTMLDialogElement>('guide-modal');
  const closeGuideButton = byId<HTMLButtonElement>('close-guide');
  const guideTitle = byId<HTMLElement>('guide-title');
  const guideKicker = byId<HTMLElement>('guide-kicker');
  const guideBody = byId<HTMLElement>('guide-body');
  const guideStepCount = byId<HTMLElement>('guide-step-count');
  const guideProgressBar = byId<HTMLElement>('guide-progress-bar');
  const guidePrevButton = byId<HTMLButtonElement>('guide-prev');
  const guideNextButton = byId<HTMLButtonElement>('guide-next');
  const guideDoneButton = byId<HTMLButtonElement>('guide-done');
  const guideStatus = byId<HTMLElement>('guide-status');

  const telemetryCount = byId<HTMLElement>('telemetry-count');
  const telemetryList = byId<HTMLElement>('telemetry-list');
  const telemetryClearButton = byId<HTMLButtonElement>('telemetry-clear');
  const attackTamperButton = byId<HTMLButtonElement>('attack-tamper');
  const attackSybilButton = byId<HTMLButtonElement>('attack-sybil');
  const attackStemButton = byId<HTMLButtonElement>('attack-stem');
  const adversaryStatus = byId<HTMLElement>('adversary-status');

  /* ------------------------------------------------------------------ state */

  let identity = generateIdentity();
  let trustGraph = new TrustGraph(identity.publicKey);
  let trustBusy = false;
  let attackBusy = false;
  let lastPacketJson = '';
  let miningController: AbortController | null = null;
  let lastProgressPaint = 0;
  let networkRefreshTimer: ReturnType<typeof setTimeout> | null = null;
  let manualBusy = false;
  let feedFilter: FeedFilter = 'all';
  let composerMode: ComposerMode = 'post';
  let receiptBytes: Uint8Array | null = null;
  let receiptDigest = '';
  let pendingVideo: VideoSlice | null = null;
  let pendingVideoUrl: string | null = null;
  let guideStep = 0;
  let guideTarget: HTMLElement | null = null;
  let commandCursor = -1;
  const commandHistory: string[] = [];
  const mediaBlobUrls = new Map<string, string>();
  const mediaAssembling = new Set<string>();
  const mediaRequested = new Set<string>();

  const store = new SporeStore({
    trustScore: (pubkey) => trustGraph.score(pubkey),
    admit: (packet) => !trustGraph.isMuted(packet.pubkey),
  });

  const telemetry = new Telemetry({ maxHistory: LOG_LIMIT });
  const swarm = new Swarm();
  const logEntries: LogEntry[] = [];

  const mediaSwarm = new MediaSwarm({
    transport: swarm,
    onProgress: (manifest, available) => {
      updateMediaSlots(manifest, available);
    },
    onComplete: (manifest, blob) => {
      applyMediaBlob(manifest, blob);
      void mediaSwarm.announce(manifest);
      appendLog(
        'media:complete',
        'VERIFIED',
        `media=${manifest.media_id.slice(0, 16)}… · chunks=${manifest.total_chunks} · ` +
          `bytes=${manifest.size} · assembly=sha256-ok`,
        'verified',
      );
    },
    onError: (message, mediaId) => {
      appendLog(
        'media:drop',
        'DROP',
        `${mediaId !== undefined ? `media=${mediaId.slice(0, 16)}… · ` : ''}${message}`,
        'drop',
      );
      if (mediaId !== undefined) updateMediaError(mediaId, message);
      setStatus(feedStatus, `media · ${message}`, 'error');
    },
  });

  /* ------------------------------------------------------------------ shell */

  function renderIdentity(): void {
    fingerprintEl.textContent = identity.fingerprint;
    pubkeyEl.textContent = `spore:0x${identity.publicKey}`;
    pubkeyEl.title = identity.publicKey;
  }

  function renderPowLabel(): void {
    const bits = Number(powSlider.value);
    powOutput.textContent = `${bits} bits · ~${formatCount(2 ** bits)} hashes`;
    if (miningController === null) {
      powRate.textContent = `idle · 0 h/s · target ${formatCount(2 ** bits)}`;
    }
  }

  function renderStoreStatus(report?: StoreLoadReport): void {
    const status = store.status;
    const seedSuffix = status.seedPackets > 0 ? ` · ${status.seedPackets} seed` : '';
    storeStatus.textContent =
      `${BACKEND_LABELS[status.backend]} · ${status.packets} packets${seedSuffix}` +
      (status.pending ? ' · pending' : '');
    storeStatus.classList.toggle('warn', status.degraded);
    storageMode.textContent = BACKEND_LABELS[status.backend];
    const problems = report?.errors ?? [];
    if (problems.length > 0) {
      storeStatus.title = problems.join('\n');
    } else if (store.persistenceError !== null) {
      storeStatus.title = store.persistenceError;
    } else {
      storeStatus.removeAttribute('title');
    }
  }

  function rebuildTrust(): void {
    trustGraph = new TrustGraph(identity.publicKey, store.packetsSnapshot());
    store.setTrustScorer((pubkey) => trustGraph.score(pubkey));
    store.rebalance();
  }

  function appendLog(
    name: string,
    label: string,
    detail: string,
    tone: LogTone,
    at = Date.now(),
  ): void {
    logEntries.push({ at, name, label, detail, tone });
    if (logEntries.length > LOG_LIMIT) {
      logEntries.splice(0, logEntries.length - LOG_LIMIT);
    }
    renderLog();
  }

  function renderLog(): void {
    telemetryCount.textContent = `${logEntries.length} event${logEntries.length === 1 ? '' : 's'}`;
    telemetryList.replaceChildren();
    if (logEntries.length === 0) {
      telemetryList.append(makeElement('li', 'telemetry-empty', 'no events yet'));
      return;
    }
    for (const entry of [...logEntries].reverse()) {
      const item = makeElement('li', 'telemetry-item');
      item.dataset['event'] = entry.name;
      const tag = makeElement('span', 'proto-tag', entry.label);
      tag.dataset['tone'] = entry.tone;
      item.append(tag);
      const name = makeElement('span', 'telemetry-name', entry.name);
      item.append(name);
      const time = new Date(entry.at);
      item.append(
        makeElement(
          'span',
          'telemetry-time',
          Number.isNaN(time.getTime()) ? '--:--:--' : time.toISOString().slice(11, 19),
        ),
      );
      item.append(makeElement('span', 'telemetry-detail', entry.detail));
      telemetryList.append(item);
    }
  }

  function pushVerified(detail: string): void {
    appendLog('verified', 'VERIFIED', detail, 'verified');
  }

  function pushDrop(id: string, peerId: string, reason: string, detail: string): void {
    telemetry.emit('pkt:drop', { id, peerId, reason, detail });
  }

  function formatTelemetryEvent(event: TelemetryEvent): string {
    const parts: string[] = [];
    for (const [key, value] of Object.entries(event.data)) {
      const rendered = value === null ? 'null' : String(value);
      parts.push(`${key}=${rendered.length > 96 ? `${rendered.slice(0, 93)}…` : rendered}`);
    }
    return parts.length === 0 ? '—' : parts.join(' · ');
  }

  function shortPeerId(peerId: string): string {
    return peerId.length > 18 ? `${peerId.slice(0, 10)}…${peerId.slice(-5)}` : peerId;
  }

  /* ------------------------------------------------------------------ media */

  function mediaCards(mediaId: string): HTMLElement[] {
    return [...document.querySelectorAll<HTMLElement>(`.feed-media[data-media-id="${mediaId}"]`)];
  }

  function mediaTone(status: HTMLElement, text: string, tone: Tone): void {
    status.textContent = text;
    if (tone === 'idle') delete status.dataset['tone'];
    else status.dataset['tone'] = tone;
  }

  function applyMediaBlob(manifest: MediaManifest, blob: Blob): void {
    if (typeof URL.createObjectURL !== 'function') return;
    const previous = mediaBlobUrls.get(manifest.media_id);
    if (previous !== undefined) URL.revokeObjectURL(previous);
    const url = URL.createObjectURL(blob);
    mediaBlobUrls.set(manifest.media_id, url);
    for (const card of mediaCards(manifest.media_id)) {
      card.dataset['ready'] = 'true';
      const video = card.querySelector('video');
      if (video !== null) {
        video.src = url;
        video.hidden = false;
      }
      const status = card.querySelector<HTMLElement>('.media-status');
      if (status !== null) {
        mediaTone(
          status,
          `${manifest.total_chunks}/${manifest.total_chunks} chunks · sha256 verified · ${formatBytes(
            manifest.size,
          )}`,
          'ok',
        );
      }
      const bar = card.querySelector<HTMLElement>('.media-progress > span');
      if (bar !== null) bar.style.width = '100%';
    }
  }

  function updateMediaSlots(manifest: MediaManifest, available: readonly number[]): void {
    const have = available.length;
    const total = manifest.total_chunks;
    const percent = total === 0 ? 0 : Math.min(100, (have / total) * 100);
    const readyUrl = mediaBlobUrls.get(manifest.media_id);
    for (const card of mediaCards(manifest.media_id)) {
      card.dataset['chunks'] = String(have);
      const bar = card.querySelector<HTMLElement>('.media-progress > span');
      if (bar !== null) bar.style.width = `${percent.toFixed(1)}%`;
      const status = card.querySelector<HTMLElement>('.media-status');
      if (readyUrl !== undefined) {
        if (status !== null) {
          mediaTone(
            status,
            `${total}/${total} chunks · sha256 verified · playing locally`,
            'ok',
          );
        }
        continue;
      }
      if (status !== null) {
        const tone: Tone = have === total ? 'ok' : swarm.peerIds().length > 0 ? 'busy' : 'idle';
        mediaTone(
          status,
          have === total
            ? `${total}/${total} chunks · assembling verified blob…`
            : `${have}/${total} chunks · ${formatBytes(manifest.size)} · ` +
                (swarm.peerIds().length > 0 ? 'fetching from swarm' : 'waiting for peers or inline carrier'),
          tone,
        );
      }
    }
    if (have === total) void ensureMediaPlayback(manifest);
  }

  function updateMediaError(mediaId: string, message: string): void {
    for (const card of mediaCards(mediaId)) {
      const status = card.querySelector<HTMLElement>('.media-status');
      if (status !== null) mediaTone(status, message, 'error');
    }
  }

  async function ensureMediaPlayback(manifest: MediaManifest): Promise<void> {
    if (mediaBlobUrls.has(manifest.media_id) || mediaAssembling.has(manifest.media_id)) return;
    mediaAssembling.add(manifest.media_id);
    try {
      const blob = await assembleVideoBlob(manifest);
      if (blob !== null) {
        applyMediaBlob(manifest, blob);
        appendLog(
          'media:play',
          'VERIFIED',
          `media=${manifest.media_id.slice(0, 16)}… · bytes=${blob.size} · ` +
            `chunks=${manifest.total_chunks} · hash=ok`,
          'verified',
        );
      }
    } finally {
      mediaAssembling.delete(manifest.media_id);
    }
  }

  async function refreshMediaCard(manifest: MediaManifest): Promise<void> {
    mediaSwarm.registerManifest(manifest);
    let available = await availableChunks(manifest);
    updateMediaSlots(manifest, available);
    if (available.length === manifest.total_chunks) {
      await ensureMediaPlayback(manifest);
      return;
    }
    if (manifest.inline_data_b64 !== undefined) {
      const imported = await importInlineMedia(manifest);
      available = await availableChunks(manifest);
      updateMediaSlots(manifest, available);
      if (imported) void mediaSwarm.announce(manifest);
      if (available.length === manifest.total_chunks) {
        await ensureMediaPlayback(manifest);
        return;
      }
    }
    if (swarm.peerIds().length > 0 && !mediaRequested.has(manifest.media_id)) {
      mediaRequested.add(manifest.media_id);
      mediaSwarm.request(manifest);
    }
  }

  function appendVideoCard(item: HTMLElement, manifest: MediaManifest): void {
    const card = makeElement('div', 'feed-media');
    card.dataset['mediaId'] = manifest.media_id;
    card.dataset['ready'] = 'false';
    card.dataset['chunks'] = '0';

    const meta = makeElement('div', 'media-meta');
    meta.append(
      makeElement('strong', undefined, `${formatBytes(manifest.size)} · ${manifest.total_chunks} chunks`),
    );
    meta.append(makeElement('span', undefined, manifest.mime));
    card.append(meta);

    const video = document.createElement('video');
    video.controls = true;
    video.playsInline = true;
    video.preload = 'metadata';
    video.hidden = true;
    video.setAttribute('playsinline', '');
    video.setAttribute('aria-label', `Video attachment ${manifest.file_name}`);
    card.append(video);

    const progress = makeElement('div', 'media-progress');
    progress.append(makeElement('span'));
    card.append(progress);

    const status = makeElement('p', 'media-status', 'checking local chunk cache…');
    card.append(status);

    item.append(card);
    void refreshMediaCard(manifest);
  }

  function registerStoredMedia(): void {
    for (const packet of store.packetsSnapshot()) {
      if (packet.media_manifest !== undefined) {
        mediaSwarm.registerManifest(packet.media_manifest);
      }
    }
  }

  /* ------------------------------------------------------------------- feed */

  function matchesFilter(packet: SporePacket, relation: TrustRelation): boolean {
    if (feedFilter === '2hop') {
      return relation === 'self' || relation === 'direct' || relation === 'second-hop';
    }
    if (feedFilter === 'pow') {
      return packet.pow_bits >= HIGH_POW_BITS;
    }
    return true;
  }

  function receiptDetail(packet: SporePacket): HydraReceiptContent | null {
    try {
      return parseHydraReceipt(packet);
    } catch {
      return null;
    }
  }

  function appendReceiptCard(item: HTMLElement, packet: SporePacket): void {
    const receipt = receiptDetail(packet);
    const card = makeElement('div', 'receipt-card');
    if (receipt === null) {
      card.append(makeElement('p', 'receipt-proof', 'Malformed Hydra receipt content.'));
      item.append(card);
      return;
    }
    const verification = verifyHydraReceipt(packet);
    const grid = makeElement('dl', 'receipt-grid');

    const addPair = (label: string, value: string | HTMLElement): void => {
      grid.append(makeElement('dt', undefined, label));
      const dd = makeElement('dd');
      if (typeof value === 'string') dd.textContent = value;
      else dd.append(value);
      grid.append(dd);
    };

    const anchor = makeElement('a', undefined, receipt.url);
    anchor.href = receipt.url;
    anchor.target = '_blank';
    anchor.rel = 'noreferrer noopener';
    addPair('external anchor', anchor);
    addPair('source sha256', makeElement('code', undefined, receipt.source_sha256));
    addPair('source kind', receipt.source_kind);
    addPair('committed', `${formatTimestamp(receipt.committed_at)} · ${receipt.committed_at}`);
    addPair('packet id', makeElement('code', undefined, packet.id));
    if (receipt.note !== undefined) addPair('note', receipt.note);
    card.append(grid);

    const verdict = makeElement(
      'p',
      'receipt-verdict',
      verification.ok
        ? `✓ verified commit · ${verification.checks.signature ? 'schnorr ok' : 'signature?'} · ${
            verification.checks.timestamp ? 'timestamp bound' : 'timestamp mismatch'
          }`
        : `✕ invalid receipt · ${verification.reason ?? 'verification failed'}`,
    );
    verdict.dataset['ok'] = String(verification.ok);
    card.append(verdict);

    if (verification.ok) {
      card.append(makeElement('pre', 'receipt-proof', receiptProofText(packet)));
      const copyProof = makeElement('button', 'ghost small', 'copy proof');
      copyProof.type = 'button';
      copyProof.style.margin = '0 10px 10px';
      copyProof.addEventListener('click', () => {
        void copyText(receiptProofText(packet), feedStatus);
      });
      card.append(copyProof);
    }
    item.append(card);
  }

  function renderFeed(): void {
    const items = store
      .packetsSnapshot()
      .filter((packet) => packet.kind === 'post' || packet.kind === 'receipt');
    const visible = items
      .filter((packet) => {
        if (trustGraph.score(packet.pubkey) <= 0) return false;
        if (!trustGraph.admit(packet) && !store.isSeedPacket(packet.id)) return false;
        return matchesFilter(packet, trustGraph.explain(packet.pubkey).relation);
      })
      .sort((a, b) => {
        const scoreDelta = trustGraph.score(b.pubkey) - trustGraph.score(a.pubkey);
        if (scoreDelta !== 0) return scoreDelta;
        if (a.created_at !== b.created_at) return b.created_at - a.created_at;
        return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
      })
      .slice(0, FEED_LIMIT);

    feedEl.replaceChildren();

    if (visible.length === 0) {
      const message =
        feedFilter !== 'all'
          ? 'No packets match this trust filter yet.'
          : store.size === 0
            ? 'No packets yet. Seal one above, import a SPOR PNG, or open a snapshot.'
            : 'No admitted packets yet. Unknown authors need enough proof of work; muted authors are hidden.';
      feedEl.append(makeElement('p', 'feed-empty', message));
    }

    for (const packet of visible) {
      const explanation = trustGraph.explain(packet.pubkey);
      const verification = verifyPacket(packet);
      const item = makeElement('article', 'feed-item');
      item.dataset['id'] = packet.id;
      item.dataset['relation'] = explanation.relation;
      item.dataset['kind'] = packet.kind;
      if (store.isSeedPacket(packet.id)) item.dataset['seed'] = 'true';

      const head = makeElement('div', 'feed-head');
      const author = makeElement('code', 'feed-author', fingerprintOf(packet.pubkey));
      author.title = packet.pubkey;
      head.append(author);

      const verifiedBadge = makeElement(
        'span',
        'verified-badge',
        packet.kind === 'receipt'
          ? verifyHydraReceipt(packet).ok
            ? '✓ receipt verified'
            : '✕ receipt invalid'
          : verification.ok
            ? '✓ verified'
            : '✕ invalid',
      );
      verifiedBadge.dataset['ok'] = String(
        packet.kind === 'receipt' ? verifyHydraReceipt(packet).ok : verification.ok,
      );
      head.append(verifiedBadge);

      const scoreTag = makeElement(
        'span',
        'score-tag',
        `${explanation.score.toFixed(1)} ${RELATION_LABELS[explanation.relation]}`,
      );
      scoreTag.dataset['relation'] = explanation.relation;
      head.append(scoreTag);

      const tierBadge = makeElement('span', 'tier-badge', TIER_LABELS[explanation.relation]);
      tierBadge.dataset['tier'] = TIER_LABELS[explanation.relation];
      head.append(tierBadge);

      if (store.isSeedPacket(packet.id)) {
        head.append(makeElement('span', 'tier-badge', 'SEED'));
      }

      const phaseLabel =
        packet.dandelion_phase === 'stem'
          ? `stem ${packet.hop_count}`
          : `fluff ${packet.hop_count}`;
      head.append(
        makeElement(
          'span',
          'feed-meta',
          `${packet.pow_bits} bits · ${phaseLabel} · ${formatTimestamp(packet.created_at)}`,
        ),
      );
      item.append(head);

      const receipt = packet.kind === 'receipt' ? receiptDetail(packet) : null;
      item.append(
        makeElement(
          'p',
          'feed-content',
          receipt !== null
            ? `HYDRA RECEIPT · ${platformLabel(receipt.platform)} · ${receipt.url}`
            : packet.content,
        ),
      );

      if (packet.kind === 'receipt') appendReceiptCard(item, packet);
      if (packet.media_manifest !== undefined) appendVideoCard(item, packet.media_manifest);

      const foot = makeElement('div', 'feed-foot');
      const idLabel = makeElement('code', 'feed-id', `id ${packet.id.slice(0, 16)}…`);
      idLabel.title = packet.id;
      if (packet.reply_to !== undefined) {
        idLabel.textContent =
          `${idLabel.textContent ?? ''} · reply ${packet.reply_to.slice(0, 10)}…`;
      }
      foot.append(idLabel);

      const actions = makeElement('div', 'feed-actions');
      const stegoButton = makeElement('button', 'ghost', 'Pack into Stego PNG');
      stegoButton.type = 'button';
      stegoButton.addEventListener('click', () => {
        void packIntoStego(packet);
      });
      actions.append(stegoButton);

      if (packet.pubkey !== identity.publicKey) {
        if (explanation.relation !== 'direct' && explanation.relation !== 'second-hop') {
          const follow = makeElement('button', 'ghost', 'follow');
          follow.type = 'button';
          follow.disabled = trustBusy;
          follow.addEventListener('click', () => {
            void handleTrust('follow', packet.pubkey);
          });
          actions.append(follow);

          const vouch = makeElement('button', 'ghost', 'vouch');
          vouch.type = 'button';
          vouch.disabled = trustBusy;
          vouch.addEventListener('click', () => {
            void handleTrust('vouch', packet.pubkey);
          });
          actions.append(vouch);
        }
        const mute = makeElement('button', 'ghost danger', 'mute');
        mute.type = 'button';
        mute.disabled = trustBusy;
        mute.addEventListener('click', () => {
          void handleTrust('mute', packet.pubkey);
        });
        actions.append(mute);
      }
      foot.append(actions);
      item.append(foot);
      feedEl.append(item);
    }

    const filterLabel =
      feedFilter === 'all' ? 'all verified' : feedFilter === '2hop' ? '2-hop' : 'high pow';
    feedCount.textContent =
      `${visible.length} admitted · ${items.length} items · ${store.size} packets · ${filterLabel}` +
      (store.seedPackets > 0 ? ` · ${store.seedPackets} from seed` : '');
  }

  /* ------------------------------------------------------------------- mesh */

  function renderPeers(): void {
    const peers = swarm.peersInfo();
    peerCount.textContent = String(peers.length);
    peerList.replaceChildren();
    if (peers.length === 0) {
      peerList.append(makeElement('li', 'peer-empty', 'no peers connected'));
      return;
    }
    for (const peer of peers) {
      const item = makeElement('li', 'peer-item');
      const id = makeElement('code', 'peer-id', shortPeerId(peer.id));
      id.title = peer.id;
      item.append(id);

      const routes = makeElement('div', 'peer-routes');
      for (const transport of peer.transports) {
        const tag = makeElement('span', 'route-tag', transportLabel(transport));
        tag.dataset['transport'] = transport;
        routes.append(tag);
      }
      const roomNames = peer.rooms
        .map((room) =>
          room === 'spore-global-v1' ? 'global' : room.replace(/^spore-topic-/, '#'),
        )
        .slice(0, 4);
      for (const room of roomNames) {
        routes.append(makeElement('span', 'route-tag', room));
      }
      if (peer.rooms.length > roomNames.length) {
        routes.append(
          makeElement('span', 'route-tag', `+${peer.rooms.length - roomNames.length}`),
        );
      }
      item.append(routes);
      peerList.append(item);
    }
  }

  function renderMesh(): void {
    const peers = swarm.peersInfo();
    meshConnectButton.disabled = swarm.isJoined;
    meshDisconnectButton.disabled = !swarm.isJoined;
    peersStat.textContent = String(peers.length);
    // relayCount is the configured endpoint set, not live sockets; show zero
    // until signaling is actually joined so the header never contradicts OFFLINE.
    relaysStat.textContent = String(swarm.isJoined ? swarm.relayCount : 0);
    if (swarm.isJoined) {
      nodePill.dataset['state'] = 'joined';
      nodeStatusText.textContent = 'MESH ACTIVE';
      setStatus(
        meshStatus,
        `${swarm.rooms.length} rooms · ${swarm.relayCount} relays · ${peers.length} peer${
          peers.length === 1 ? '' : 's'
        }`,
        peers.length > 0 ? 'ok' : 'busy',
      );
      meshSummary.textContent =
        `Signaling live on ${swarm.relayCount} public relays. Peers discover each other in ` +
        `${swarm.rooms.length} room${swarm.rooms.length === 1 ? '' : 's'} and sync only missing packets.`;
    } else if (peers.length > 0) {
      nodePill.dataset['state'] = 'direct';
      nodeStatusText.textContent = 'DIRECT PEERS';
      setStatus(
        meshStatus,
        `signaling off · ${peers.length} direct peer${peers.length === 1 ? '' : 's'}`,
        'ok',
      );
    } else {
      nodePill.dataset['state'] = 'offline';
      nodeStatusText.textContent = 'OFFLINE';
      setStatus(meshStatus, 'offline · zero requests', 'idle');
      meshSummary.textContent =
        'Signaling is off until you join. Peers are discovered simultaneously over public ' +
        'Nostr relays and BitTorrent WebSocket trackers, then talk directly over WebRTC.';
    }
    renderPeers();
  }

  /* ---------------------------------------------------------------- networking */

  const scheduleNetworkRefresh = (): void => {
    if (networkRefreshTimer !== null) return;
    networkRefreshTimer = setTimeout(() => {
      networkRefreshTimer = null;
      rebuildTrust();
      renderFeed();
      renderStoreStatus();
      void store.flush().then(() => renderStoreStatus());
    }, 40);
  };

  const dandelion = new DandelionRouter({
    transport: swarm,
    telemetry,
    ingest: (packet) => store.append(packet),
    has: (id) => store.get(id) !== undefined,
    onAccepted: scheduleNetworkRefresh,
  });

  const gossip = new GossipEngine({
    transport: swarm,
    store,
    telemetry,
    autoSyncMs: 45_000,
    onAccepted: scheduleNetworkRefresh,
  });

  telemetry.subscribe((event) => {
    appendLog(event.name, LOG_LABELS[event.name], formatTelemetryEvent(event), LOG_TONES[event.name], event.at);
  });

  swarm.onEvent((event) => {
    switch (event.type) {
      case 'status':
        renderMesh();
        if (event.status === 'joined') registerStoredMedia();
        setStatus(
          meshNote,
          event.status === 'joined'
            ? `joined ${event.rooms.length} rooms · ${event.relays} relays · discovering peers…`
            : swarm.peersInfo().length > 0
              ? 'signaling left · direct SDP peers remain connected'
              : 'signaling left · offline',
          event.status === 'joined' ? 'busy' : 'idle',
        );
        break;
      case 'peer:join':
        telemetry.emit('peer:join', {
          peerId: event.peer.id,
          transports: event.peer.transports.join(','),
          rooms: event.peer.rooms.join(','),
        });
        gossip.onPeerJoin(event.peer.id);
        mediaSwarm.onPeerJoin(event.peer.id);
        renderMesh();
        setStatus(
          meshNote,
          `peer joined · ${event.peer.transports.map(transportLabel).join(' + ')} · ${shortPeerId(
            event.peer.id,
          )}`,
          'ok',
        );
        break;
      case 'peer:leave':
        telemetry.emit('peer:leave', {
          peerId: event.peerId,
          transports: event.transports.join(','),
        });
        gossip.onPeerLeave(event.peerId);
        mediaSwarm.onPeerLeave(event.peerId);
        renderMesh();
        setStatus(meshNote, `peer left · ${shortPeerId(event.peerId)}`, 'idle');
        break;
      case 'error':
        setStatus(meshNote, event.message, 'error');
        break;
      case 'manual': {
        const peerSuffix = event.peerId === undefined ? '' : ` · ${shortPeerId(event.peerId)}`;
        if (event.stage === 'connected') {
          setStatus(manualStatus, `direct channel open${peerSuffix}`, 'ok');
          renderMesh();
        } else if (event.stage === 'closed') {
          setStatus(manualStatus, `direct channel closed${peerSuffix}`, 'idle');
          renderMesh();
        } else if (event.stage === 'error') {
          setStatus(manualStatus, event.message ?? 'direct handshake failed', 'error');
        } else if (event.message !== undefined) {
          setStatus(manualStatus, `${event.message}${peerSuffix}`, 'ok');
        }
        break;
      }
    }
  });

  swarm.onMessage(({ peerId, data }) => {
    const parsed = parseWireMessage(data);
    if (!parsed.ok) {
      telemetry.emit('pkt:drop', {
        peerId,
        reason: 'malformed-wire',
        detail: parsed.reason,
      });
      return;
    }
    if (isMediaMessage(parsed.message)) {
      mediaSwarm.handleMessage(peerId, parsed.message);
      return;
    }
    const handledBySync = gossip.handleMessage(peerId, parsed.message);
    const handledByRouting = dandelion.handleMessage(peerId, parsed.message);
    if (!handledBySync && !handledByRouting) {
      telemetry.emit('pkt:drop', {
        peerId,
        reason: 'unknown-wire-type',
        detail: parsed.message.t,
      });
    }
  });

  gossip.start();

  /* ------------------------------------------------------------------ trust */

  function publishOptions(): { directFluff?: boolean } {
    return dandelionToggle.checked ? {} : { directFluff: true };
  }

  function routeText(route: PublishRoute): string {
    if (route.phase === 'stem' && route.target !== null) {
      return `stem → ${shortPeerId(route.target)}`;
    }
    return dandelionToggle.checked ? 'fluff · no stem peers' : 'fluff · direct broadcast';
  }

  async function handleTrust(action: TrustAction, target: string): Promise<void> {
    if (trustBusy) return;
    trustBusy = true;
    renderFeed();
    setStatus(trustStatus, `sealing ${action} for ${fingerprintOf(target)}…`, 'busy');
    setStatus(feedStatus, `sealing ${action} for ${fingerprintOf(target)}…`, 'busy');
    try {
      const packet = await sealPacket(
        { kind: 'trust', content: encodeTrustContent(action, target) },
        identity,
        { powBits: TRUST_POW_BITS },
      );
      const route = dandelion.publish(packet, publishOptions());
      if (!route.accepted) {
        throw new Error(`trust packet rejected: ${route.reason ?? 'unknown'}`);
      }
      trustGraph.addPacket(packet);
      store.rebalance();
      const persisted = await store.flush();
      renderFeed();
      renderStoreStatus();
      const routeLabel = routeText(route);
      const message =
        `${action} sealed for ${fingerprintOf(target)} · ${routeLabel}` +
        (persisted ? ' · stored' : ' · memory only');
      setStatus(feedStatus, message, persisted ? 'ok' : 'error');
      setStatus(trustStatus, message, persisted ? 'ok' : 'error');
      pushVerified(`trust:${action} target=${target} · sig=ok · ${routeLabel}`);
    } catch (error) {
      setStatus(trustStatus, errorMessage(error), 'error');
      setStatus(feedStatus, errorMessage(error), 'error');
    } finally {
      trustBusy = false;
      renderFeed();
    }
  }

  function handleManualTrust(action: TrustAction): void {
    const target = trustPubkey.value.trim().toLowerCase();
    if (target.length === 0) {
      setStatus(trustStatus, 'paste a 32-byte hex pubkey first', 'error');
      trustPubkey.focus();
      return;
    }
    if (!isValidPublicKey(target)) {
      setStatus(trustStatus, 'that is not a valid secp256k1 x-only pubkey', 'error');
      trustPubkey.focus();
      return;
    }
    if (target === identity.publicKey) {
      setStatus(trustStatus, 'cannot vouch or mute your own key', 'error');
      return;
    }
    void handleTrust(action, target);
  }

  /* ----------------------------------------------------------------- filter */

  function setFeedFilter(filter: FeedFilter): void {
    feedFilter = filter;
    filterAll.classList.toggle('is-active', filter === 'all');
    filter2Hop.classList.toggle('is-active', filter === '2hop');
    filterPow.classList.toggle('is-active', filter === 'pow');
    renderFeed();
  }

  /* --------------------------------------------------------------- composer */

  function setComposerMode(mode: ComposerMode): void {
    composerMode = mode;
    modePostButton.classList.toggle('is-active', mode === 'post');
    modeReceiptButton.classList.toggle('is-active', mode === 'receipt');
    postFields.hidden = mode === 'receipt';
    receiptFields.hidden = mode === 'post';
    sealButton.textContent = mode === 'receipt' ? 'mine & seal receipt' : 'mine & seal post';
  }

  const VIDEO_HINT =
    'MP4 or WebM. Sliced into 64 KiB chunks, verified with SHA-256, and seeded to peers. ' +
    'Clips up to 1.5 MB also embed inline for zero-peer offline playback.';

  function clearPendingVideo(): void {
    if (pendingVideoUrl !== null && typeof URL.revokeObjectURL === 'function') {
      URL.revokeObjectURL(pendingVideoUrl);
    }
    pendingVideo = null;
    pendingVideoUrl = null;
    videoPreview.removeAttribute('src');
    videoPreview.hidden = true;
    videoAttachTag.textContent = 'none';
    videoHint.textContent = VIDEO_HINT;
    clearVideoButton.hidden = true;
    videoFileInput.value = '';
    setStatus(videoStatus, '', 'idle');
  }

  function renderPendingVideo(slice: VideoSlice, sourceLabel: string): void {
    const { manifest } = slice;
    videoAttachTag.textContent = `${manifest.total_chunks} chunks`;
    videoHint.textContent =
      `${sourceLabel} · ${formatBytes(manifest.size)} · ${manifest.mime}` +
      (manifest.inline_data_b64 !== undefined ? ' · inline carrier available' : '') +
      ` · sha256 ${manifest.media_id.slice(0, 16)}…`;
    clearVideoButton.hidden = false;
  }

  async function handleVideoFile(): Promise<void> {
    const file = videoFileInput.files?.[0];
    if (file === undefined) return;
    setStatus(videoStatus, `slicing ${file.name} into 64 KiB chunks…`, 'busy');
    try {
      const slice = await ingestVideoFile(file);
      if (pendingVideoUrl !== null && typeof URL.revokeObjectURL === 'function') {
        URL.revokeObjectURL(pendingVideoUrl);
      }
      pendingVideo = slice;
      pendingVideoUrl =
        typeof URL.createObjectURL === 'function' ? URL.createObjectURL(file) : null;
      if (pendingVideoUrl !== null) {
        videoPreview.src = pendingVideoUrl;
        videoPreview.hidden = false;
      }
      renderPendingVideo(slice, file.name);
      mediaSwarm.registerManifest(slice.manifest);
      await mediaSwarm.announce(slice.manifest);
      setStatus(
        videoStatus,
        `${slice.manifest.total_chunks} chunks verified and cached · ` +
          `${formatBytes(slice.manifest.size)} · ` +
          (swarm.peerIds().length > 0
            ? `announced to ${swarm.peerIds().length} peer${swarm.peerIds().length === 1 ? '' : 's'}`
            : 'will seed when peers connect'),
        'ok',
      );
      appendLog(
        'media:ingest',
        'VERIFIED',
        `file=${file.name} · bytes=${slice.manifest.size} · chunks=${slice.manifest.total_chunks} · ` +
          `sha256=${slice.manifest.media_id.slice(0, 16)}… · inline=${
            slice.manifest.inline_data_b64 !== undefined ? 'yes' : 'no'
          }`,
        'verified',
      );
    } catch (error) {
      setStatus(videoStatus, `video import failed: ${errorMessage(error)}`, 'error');
    } finally {
      videoFileInput.value = '';
    }
  }

  function updateReceiptDigest(): void {
    receiptDigestEl.textContent =
      receiptDigest.length > 0 ? `sha256:${receiptDigest}` : 'not computed';
  }

  function clearReceiptSource(): void {
    receiptBytes = null;
    receiptDigest = '';
    receiptFileInput.value = '';
    receiptSourceInput.value = '';
    updateReceiptDigest();
    setStatus(receiptStatus, '', 'idle');
  }

  async function handleReceiptFile(): Promise<void> {
    const file = receiptFileInput.files?.[0];
    if (file === undefined) {
      receiptBytes = null;
      receiptDigest = '';
      updateReceiptDigest();
      return;
    }
    if (file.size > MAX_RECEIPT_SOURCE_BYTES) {
      receiptBytes = null;
      receiptDigest = '';
      updateReceiptDigest();
      setStatus(
        receiptStatus,
        `media exceeds the ${Math.floor(MAX_RECEIPT_SOURCE_BYTES / (1024 * 1024))} MiB cap`,
        'error',
      );
      receiptFileInput.value = '';
      return;
    }
    setStatus(receiptStatus, `hashing ${file.name}…`, 'busy');
    try {
      const buffer = await file.arrayBuffer();
      receiptBytes = new Uint8Array(buffer);
      receiptDigest = hashMediaBytes(receiptBytes);
      receiptSourceInput.value = '';
      updateReceiptDigest();
      setStatus(receiptStatus, `media digest ready · ${file.name}`, 'ok');
    } catch (error) {
      receiptBytes = null;
      receiptDigest = '';
      updateReceiptDigest();
      setStatus(receiptStatus, errorMessage(error), 'error');
    }
  }

  function readReceiptSource(): { readonly source: ReceiptSource; readonly label: string } {
    if (receiptBytes !== null) {
      return { source: { kind: 'media', value: receiptBytes }, label: 'media' };
    }
    const text = receiptSourceInput.value;
    if (text.trim().length === 0) {
      throw new Error('provide original text or choose a media file to hash');
    }
    return { source: { kind: 'text', value: text }, label: 'text' };
  }

  function beginMining(bits: number): AbortController {
    const controller = new AbortController();
    miningController = controller;
    lastProgressPaint = 0;
    sealButton.disabled = true;
    rotateButton.disabled = true;
    cancelButton.hidden = false;
    packetResult.hidden = true;
    progressBar.style.width = '0%';
    powRate.textContent = '0 h/s';
    setStatus(mineStatus, `mining ${bits} bits…`, 'busy');
    return controller;
  }

  function endMining(): void {
    miningController = null;
    sealButton.disabled = false;
    rotateButton.disabled = false;
    cancelButton.hidden = true;
  }

  function onMiningProgress(progress: MiningProgress, bits: number): void {
    const now = performance.now();
    if (now - lastProgressPaint < 100) return;
    lastProgressPaint = now;
    const expected = 2 ** bits;
    const probability = 1 - Math.exp(-progress.attempts / expected);
    progressBar.style.width = `${(Math.min(probability, 0.985) * 100).toFixed(1)}%`;
    powRate.textContent = `${formatCount(progress.hashesPerSecond)} h/s`;
    setStatus(
      mineStatus,
      `mining · ${formatCount(progress.attempts)} hashes · ` +
        `${formatCount(progress.hashesPerSecond)} h/s`,
      'busy',
    );
  }

  function renderResult(
    packet: SporePacket,
    verification: PacketVerificationResult,
    elapsedMs: number,
  ): void {
    if (verification.ok) {
      verdictEl.textContent = `verified · ${verification.leadingZeroBits} zero bits`;
      verdictEl.dataset['ok'] = 'true';
      resultPow.textContent =
        `${packet.pow_bits} bits required · nonce ${packet.pow_nonce}` +
        ` · ${verification.leadingZeroBits} leading zero bits`;
    } else {
      verdictEl.textContent = `rejected · ${verification.reason}`;
      verdictEl.dataset['ok'] = 'false';
      resultPow.textContent = verification.detail;
    }
    resultId.textContent = packet.id;
    resultTime.textContent = `${(elapsedMs / 1000).toFixed(2)} s`;
    resultSig.textContent = packet.sig;
    resultJson.textContent = JSON.stringify(packet, null, 2);
    lastPacketJson = JSON.stringify(packet);
    packetResult.hidden = false;
  }

  async function publishSealed(
    packet: SporePacket,
    verification: PacketVerificationResult,
    elapsedMs: number,
    kindLabel: string,
  ): Promise<void> {
    const route = dandelion.publish(packet, publishOptions());
    if (!route.accepted) {
      setStatus(
        mineStatus,
        `sealed but storage rejected it: ${route.reason ?? 'unknown'}`,
        'error',
      );
      return;
    }
    renderFeed();
    renderStoreStatus();
    void store.flush().then(() => renderStoreStatus());
    const routeLabel = routeText(route);
    const detail =
      `id=${packet.id} · kind=${kindLabel} · sig=valid · pow=${verification.ok ? verification.leadingZeroBits : '?'}` +
      ` · ${routeLabel}`;
    pushVerified(detail);
    setStatus(
      mineStatus,
      `sealed in ${(elapsedMs / 1000).toFixed(2)} s · ` +
        `${formatCount(verification.ok ? verification.leadingZeroBits : 0)} zero bits · ` +
        `signature valid · stored · ${routeLabel}`,
      'ok',
    );
  }

  async function handlePostSeal(): Promise<void> {
    const rawContent = contentEl.value;
    if (rawContent.trim().length === 0 && pendingVideo === null) {
      setStatus(mineStatus, 'write something first', 'error');
      contentEl.focus();
      return;
    }
    const content =
      rawContent.trim().length > 0 ? rawContent : (pendingVideo?.manifest.file_name ?? '');
    const video = pendingVideo;
    const bits = Number(powSlider.value);
    const controller = beginMining(bits);
    const startedAt = performance.now();
    try {
      const packet = await sealPacket(
        {
          kind: 'post',
          content,
          ...(video !== null ? { media_manifest: video.manifest } : {}),
        },
        identity,
        {
          powBits: bits,
          signal: controller.signal,
          onProgress: (progress) => onMiningProgress(progress, bits),
        },
      );
      const elapsedMs = performance.now() - startedAt;
      progressBar.style.width = '100%';
      const verification = verifyPacket(packet, { minPowBits: bits });
      renderResult(packet, verification, elapsedMs);
      if (!verification.ok) {
        setStatus(mineStatus, `self-verification failed: ${verification.detail}`, 'error');
        return;
      }
      await publishSealed(packet, verification, elapsedMs, 'post');
      if (video !== null) {
        mediaSwarm.registerManifest(video.manifest);
        await mediaSwarm.announce(video.manifest);
        setStatus(
          videoStatus,
          `published with ${video.manifest.total_chunks} verified chunks · seeding to peers`,
          'ok',
        );
      }
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        setStatus(mineStatus, 'mining cancelled', 'idle');
      } else {
        setStatus(mineStatus, errorMessage(error), 'error');
      }
      progressBar.style.width = '0%';
    } finally {
      endMining();
    }
  }

  async function handleReceiptSeal(): Promise<void> {
    const url = receiptUrlInput.value.trim();
    if (url.length === 0) {
      setStatus(receiptStatus, 'paste the external post URL first', 'error');
      receiptUrlInput.focus();
      return;
    }
    if (normalizeSocialUrl(url) === null) {
      setStatus(
        receiptStatus,
        'URL must be an Instagram, YouTube or X/Twitter post link',
        'error',
      );
      receiptUrlInput.focus();
      return;
    }
    let source: ReceiptSource;
    let sourceLabel: string;
    try {
      const read = readReceiptSource();
      source = read.source;
      sourceLabel = read.label;
    } catch (error) {
      setStatus(receiptStatus, errorMessage(error), 'error');
      return;
    }

    const bits = Number(powSlider.value);
    const controller = beginMining(bits);
    const startedAt = performance.now();
    const note = receiptNoteInput.value.trim();
    try {
      const { packet, receipt } = await createHydraReceipt({
        identity,
        url,
        source,
        ...(note.length > 0 ? { note } : {}),
        powBits: bits,
        signal: controller.signal,
        onProgress: (progress) => onMiningProgress(progress, bits),
      });
      const elapsedMs = performance.now() - startedAt;
      progressBar.style.width = '100%';
      const verification = verifyPacket(packet, { minPowBits: bits });
      renderResult(packet, verification, elapsedMs);
      if (!verification.ok) {
        setStatus(mineStatus, `self-verification failed: ${verification.detail}`, 'error');
        return;
      }
      setStatus(
        receiptStatus,
        `receipt committed · ${platformLabel(receipt.platform)} · sha256:${receipt.source_sha256}`,
        'ok',
      );
      await publishSealed(packet, verification, elapsedMs, `receipt/${sourceLabel}`);
    } catch (error) {
      if (error instanceof Error && error.name === 'AbortError') {
        setStatus(mineStatus, 'mining cancelled', 'idle');
      } else {
        setStatus(mineStatus, errorMessage(error), 'error');
        setStatus(receiptStatus, errorMessage(error), 'error');
      }
      progressBar.style.width = '0%';
    } finally {
      endMining();
    }
  }

  function handleSeal(): void {
    if (miningController !== null) return;
    if (composerMode === 'receipt') {
      void handleReceiptSeal();
      return;
    }
    void handlePostSeal();
  }

  /* -------------------------------------------------------------- stego flow */

  async function packIntoStego(packet: SporePacket): Promise<void> {
    setStatus(stegoStatus, 'rendering lossless carrier…', 'busy');
    try {
      const title =
        packet.kind === 'receipt'
          ? 'hydra censorship receipt'
          : packet.content.trim().slice(0, 80) || 'spore field note';
      const blob = await encodePacketsToStegoPng([packet], title);
      downloadBlob(blob, `spore-carrier-${packet.id.slice(0, 8)}.png`);
      setStatus(
        stegoStatus,
        `carrier exported · ${(blob.size / 1024).toFixed(1)} KiB · RGB LSB + CRC32 · ` +
          `id ${packet.id.slice(0, 12)}…`,
        'ok',
      );
      pushVerified(`stego:pack id=${packet.id} · bytes=${blob.size} · crc=sealed`);
    } catch (error) {
      setStatus(stegoStatus, `stego export failed: ${errorMessage(error)}`, 'error');
    }
  }

  async function handleStegoImport(): Promise<void> {
    const file = stegoFileInput.files?.[0];
    if (file === undefined) return;
    setStatus(stegoStatus, `decoding ${file.name}…`, 'busy');
    try {
      const result = await decodePacketsFromStegoPng(file);
      if (!result.crcValid) {
        const reason = result.reason ?? 'CRC32 mismatch';
        setStatus(stegoStatus, `import rejected · ${reason}`, 'error');
        appendLog('stego:drop', 'DROP', `file=${file.name} · ${reason}`, 'drop');
        return;
      }
      if (result.packets.length === 0) {
        setStatus(
          stegoStatus,
          `CRC verified but no valid packets${result.reason !== undefined ? ` · ${result.reason}` : ''}`,
          'error',
        );
        appendLog('stego:drop', 'DROP', `file=${file.name} · no valid packets`, 'drop');
        return;
      }
      const report = store.merge(result.packets);
      for (const packet of result.packets) {
        if (packet.media_manifest !== undefined) mediaSwarm.registerManifest(packet.media_manifest);
      }
      rebuildTrust();
      renderFeed();
      renderStoreStatus();
      const persisted = await store.flush();
      setStatus(
        stegoStatus,
        `imported ${report.added} · verified ${result.packets.length} · ` +
          `duplicates ${report.duplicates} · rejected ${result.rejected}` +
          (persisted ? ' · stored' : ' · memory only'),
        persisted ? 'ok' : 'error',
      );
      pushVerified(
        `stego:import file=${file.name} · packets=${result.packets.length} · ` +
          `added=${report.added} · crc=valid`,
      );
    } catch (error) {
      setStatus(stegoStatus, `import failed: ${errorMessage(error)}`, 'error');
    } finally {
      stegoFileInput.value = '';
    }
  }

  /* ------------------------------------------------------------- adversarial */

  function setAttackBusy(busy: boolean): void {
    attackBusy = busy;
    attackTamperButton.disabled = busy;
    attackSybilButton.disabled = busy;
    attackStemButton.disabled = busy;
  }

  async function attackTamperedSignature(): Promise<void> {
    if (attackBusy) return;
    setAttackBusy(true);
    setStatus(adversaryStatus, 'sealing a probe, then flipping its signature…', 'busy');
    try {
      const base =
        store.packetsSnapshot().find((packet) => packet.kind === 'post') ??
        (await sealPacket(
          { kind: 'post', content: `tamper probe ${Date.now()}` },
          identity,
          { powBits: 4 },
        ));
      const first = base.sig.slice(0, 1) === '0' ? '1' : '0';
      const tampered: SporePacket = { ...base, sig: `${first}${base.sig.slice(1)}` };
      const result = verifyPacket(tampered);
      if (result.ok) throw new Error('tampered signature unexpectedly verified');
      pushDrop(tampered.id, 'tamper-lab', result.reason, result.detail);
      setStatus(
        adversaryStatus,
        `DROP · tampered signature rejected at ingress · ${result.reason}`,
        'ok',
      );
    } catch (error) {
      setStatus(adversaryStatus, errorMessage(error), 'error');
    } finally {
      setAttackBusy(false);
    }
  }

  async function attackSybilSpam(): Promise<void> {
    if (attackBusy) return;
    setAttackBusy(true);
    setStatus(adversaryStatus, 'minting a zero-work sybil identity…', 'busy');
    try {
      let sybil: SporePacket | null = null;
      let failure: PacketVerificationResult | null = null;
      for (let attempt = 0; attempt < 4; attempt += 1) {
        sybil = await sealPacket(
          {
            kind: 'post',
            content: `zero-work sybil spam #${attempt} ${Date.now()}`,
          },
          identity,
          { powBits: 0 },
        );
        const check = verifyPacket(sybil, { minPowBits: HIGH_POW_BITS });
        if (!check.ok) {
          failure = check;
          break;
        }
      }
      if (sybil === null || failure === null) {
        throw new Error('zero-work probe accidentally cleared the PoW floor');
      }
      pushDrop(sybil.id, 'sybil-farm', failure.reason, failure.detail);
      setStatus(
        adversaryStatus,
        `DROP · 0 declared bits < ${HIGH_POW_BITS}-bit unknown-author floor · ${failure.reason}`,
        'ok',
      );
    } catch (error) {
      setStatus(adversaryStatus, errorMessage(error), 'error');
    } finally {
      setAttackBusy(false);
    }
  }

  async function attackStemHop(): Promise<void> {
    if (attackBusy) return;
    setAttackBusy(true);
    setStatus(adversaryStatus, 'injecting a hop-2 stem packet…', 'busy');
    try {
      const base = await sealPacket(
        { kind: 'post', content: `simulated stem hop ${Date.now()}` },
        identity,
        { powBits: 8 },
      );
      const stemmed: SporePacket = { ...base, hop_count: 2, dandelion_phase: 'stem' };
      const message: WireMessage = { v: 1, t: 'PKT_STEM', packet: stemmed };
      const handled = dandelion.handleMessage('simulated-stem-peer', message);
      appendLog(
        'simulated:stem',
        'STEM',
        `id=${stemmed.id} · injected hop=2 · handled=${String(handled)} · next hop fluffs at 3`,
        'stem',
      );
      renderFeed();
      renderStoreStatus();
      setStatus(
        adversaryStatus,
        `STEM → FLUFF · hop 2 injected, terminal fluff emitted at hop 3`,
        'ok',
      );
    } catch (error) {
      setStatus(adversaryStatus, errorMessage(error), 'error');
    } finally {
      setAttackBusy(false);
    }
  }

  /* ------------------------------------------------------------ key + quine */

  async function handleEncrypt(): Promise<void> {
    const passphrase = backupPass.value;
    if (passphrase.length === 0) {
      setStatus(backupStatus, 'enter a passphrase first', 'error');
      backupPass.focus();
      return;
    }
    encryptButton.disabled = true;
    setStatus(backupStatus, 'deriving key · 210,000 PBKDF2 rounds…', 'busy');
    await nextFrame();
    try {
      const backup: EncryptedKeyBackup = encryptIdentity(identity, passphrase, {
        createdAt: Math.floor(Date.now() / 1000),
      });
      backupJson.value = serializeKeyBackup(backup);
      setStatus(backupStatus, `encrypted backup ready for ${identity.fingerprint}`, 'ok');
    } catch (error) {
      setStatus(backupStatus, errorMessage(error), 'error');
    } finally {
      encryptButton.disabled = false;
    }
  }

  async function handleRestore(): Promise<void> {
    const passphrase = restorePass.value;
    if (passphrase.length === 0) {
      setStatus(backupStatus, 'enter the backup passphrase', 'error');
      restorePass.focus();
      return;
    }
    restoreButton.disabled = true;
    setStatus(backupStatus, 'deriving key and authenticating backup…', 'busy');
    await nextFrame();
    try {
      const backup = parseKeyBackup(backupJson.value);
      const restored = decryptIdentity(backup, passphrase);
      miningController?.abort();
      identity = restored;
      lastPacketJson = '';
      packetResult.hidden = true;
      renderIdentity();
      rebuildTrust();
      renderFeed();
      renderStoreStatus();
      setStatus(backupStatus, `adopted ${restored.fingerprint}`, 'ok');
    } catch (error) {
      setStatus(backupStatus, errorMessage(error), 'error');
    } finally {
      restoreButton.disabled = false;
    }
  }

  function handleExportQuine(): void {
    try {
      const blob = exportSporeQuine(store.packetsSnapshot(), {
        maxPackets: QUINE_PACKET_LIMIT,
        trustScore: (pubkey) => trustGraph.score(pubkey),
      });
      renderStoreStatus();
      setStatus(
        feedStatus,
        `snapshot exported · ${store.size} packets · ${(blob.size / 1024).toFixed(1)} KiB · ` +
          'public data only',
        'ok',
      );
    } catch (error) {
      setStatus(feedStatus, errorMessage(error), 'error');
    }
  }

  /* ------------------------------------------------------------------ manual */

  function setManualButtons(disabled: boolean): void {
    manualOfferButton.disabled = disabled;
    manualAcceptButton.disabled = disabled;
    manualAnswerButton.disabled = disabled;
    manualCopyButton.disabled = disabled;
  }

  async function runManualAction(
    busyText: string,
    action: () => Promise<void>,
  ): Promise<void> {
    if (manualBusy) return;
    manualBusy = true;
    setManualButtons(true);
    setStatus(manualStatus, busyText, 'busy');
    try {
      await action();
    } catch (error) {
      setStatus(manualStatus, errorMessage(error), 'error');
    } finally {
      manualBusy = false;
      setManualButtons(false);
    }
  }

  /* ------------------------------------------------------------ command bar */

  function rememberCommand(command: string): void {
    if (command.length === 0) return;
    if (commandHistory[commandHistory.length - 1] !== command) {
      commandHistory.push(command);
      if (commandHistory.length > 40) commandHistory.shift();
    }
    commandCursor = -1;
  }

  const COMMAND_HELP =
    '/join [topics] · /leave · /post <text> · /seal · /video · /import · /export · ' +
    '/filter all|2hop|pow · /receipt <url> · /vault · /bridge · /status · /diagnostics · /guide';

  function runCommand(raw: string): void {
    const trimmed = raw.trim();
    if (trimmed.length === 0) return;
    rememberCommand(trimmed);
    const space = trimmed.indexOf(' ');
    const head = (space === -1 ? trimmed : trimmed.slice(0, space)).toLowerCase();
    const arg = space === -1 ? '' : trimmed.slice(space + 1).trim();

    switch (head) {
      case '/help': {
        setStatus(commandStatus, COMMAND_HELP, 'idle');
        return;
      }
      case '/guide':
      case '/tour': {
        openGuide(0);
        setStatus(commandStatus, 'guided tour opened', 'ok');
        return;
      }
      case '/join': {
        if (arg.length > 0) topicsInput.value = arg;
        meshConnectButton.click();
        setStatus(
          commandStatus,
          `join requested · ${topicsInput.value.trim() || 'global'}`,
          'busy',
        );
        return;
      }
      case '/leave': {
        meshDisconnectButton.click();
        setStatus(commandStatus, 'signaling leave requested', 'idle');
        return;
      }
      case '/post': {
        setComposerMode('post');
        if (arg.length === 0) {
          contentEl.focus();
          setStatus(commandStatus, 'write a packet, then press /seal', 'idle');
          return;
        }
        contentEl.value = arg;
        contentEl.focus();
        setStatus(commandStatus, 'draft loaded · press /seal or mine & seal post', 'ok');
        return;
      }
      case '/seal': {
        handleSeal();
        setStatus(commandStatus, 'seal requested', 'busy');
        return;
      }
      case '/video': {
        videoFileInput.click();
        setStatus(commandStatus, 'choose a video file to slice and seed', 'busy');
        return;
      }
      case '/import': {
        stegoFileInput.click();
        setStatus(commandStatus, 'choose a SPORE PNG carrier', 'busy');
        return;
      }
      case '/export': {
        handleExportQuine();
        setStatus(commandStatus, 'quine export requested', 'ok');
        return;
      }
      case '/receipt': {
        setComposerMode('receipt');
        if (arg.length > 0) receiptUrlInput.value = arg;
        receiptUrlInput.focus();
        setStatus(
          commandStatus,
          arg.length > 0
            ? 'receipt URL loaded · add source text or media, then /seal'
            : 'paste an Instagram, YouTube, or X/Twitter URL',
          'idle',
        );
        return;
      }
      case '/filter': {
        const filter = arg.toLowerCase();
        if (filter === 'all' || filter === '2hop' || filter === 'pow') {
          setFeedFilter(filter);
          setStatus(commandStatus, `feed filter · ${filter}`, 'ok');
        } else {
          setStatus(commandStatus, 'usage: /filter all|2hop|pow', 'error');
        }
        return;
      }
      case '/vault': {
        openDialog(identityModal);
        setStatus(commandStatus, 'key vault opened', 'ok');
        return;
      }
      case '/bridge': {
        openDialog(manualBox);
        setStatus(commandStatus, 'manual SDP bridge opened', 'ok');
        return;
      }
      case '/status': {
        const mediaCount = store
          .packetsSnapshot()
          .filter((packet) => packet.media_manifest !== undefined).length;
        setStatus(
          commandStatus,
          `${store.size} packets · ${BACKEND_LABELS[store.status.backend]} · ` +
            `${swarm.peersInfo().length} peers · ${swarm.isJoined ? 'signaling on' : 'offline'} · ` +
            `${mediaCount} media manifest${mediaCount === 1 ? '' : 's'}`,
          'ok',
        );
        return;
      }
      case '/diagnostics': {
        const hidden = !appShell.classList.contains('diagnostics-hidden');
        setDiagnosticsHidden(hidden);
        setStatus(
          commandStatus,
          hidden ? 'diagnostics hidden · DOM preserved' : 'diagnostics visible',
          'ok',
        );
        return;
      }
      case '/trace': {
        setDiagnosticsHidden(false);
        telemetryList.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
        setStatus(commandStatus, 'protocol trace visible', 'ok');
        return;
      }
      case '/clear': {
        telemetry.clear();
        logEntries.length = 0;
        renderLog();
        setStatus(commandStatus, 'protocol trace cleared', 'idle');
        return;
      }
      default: {
        setStatus(
          commandStatus,
          `unknown command ${head} · type /help`,
          'error',
        );
      }
    }
  }

  /* ------------------------------------------------------------------ tour */

  function clearGuideTarget(): void {
    if (guideTarget !== null) {
      guideTarget.classList.remove('guide-focus');
      guideTarget = null;
    }
  }

  function renderGuide(): void {
    const step = GUIDE_STEPS[guideStep];
    if (step === undefined) return;
    clearGuideTarget();
    guideTitle.textContent = step.title;
    guideKicker.textContent = step.kicker;
    guideBody.replaceChildren(
      ...step.body.map((paragraph) => makeElement('p', undefined, paragraph)),
    );
    guideStepCount.textContent = `${guideStep + 1} / ${GUIDE_STEPS.length}`;
    guideProgressBar.style.width = `${((guideStep + 1) / GUIDE_STEPS.length) * 100}%`;
    guidePrevButton.disabled = guideStep === 0;
    const last = guideStep === GUIDE_STEPS.length - 1;
    guideNextButton.textContent = last ? 'finish' : 'next';
    guideDoneButton.hidden = !last;
    setStatus(
      guideStatus,
      last ? 'tour complete · every control remains available' : 'use next / back or the arrow keys',
      'idle',
    );
    if (step.target !== undefined) {
      const target = document.querySelector<HTMLElement>(step.target);
      if (target !== null) {
        guideTarget = target;
        target.classList.add('guide-focus');
        if (typeof target.scrollIntoView === 'function') {
          target.scrollIntoView({ block: 'center', behavior: 'smooth' });
        }
      }
    }
  }

  function openGuide(index = 0): void {
    guideStep = Math.min(Math.max(0, index), GUIDE_STEPS.length - 1);
    renderGuide();
    openDialog(guideModal);
  }

  function closeGuide(): void {
    clearGuideTarget();
    closeDialog(guideModal);
  }

  function setDiagnosticsHidden(hidden: boolean): void {
    appShell.classList.toggle('diagnostics-hidden', hidden);
    toggleAdvancedButton.textContent = hidden ? 'show diagnostics' : 'hide diagnostics';
    toggleAdvancedButton.setAttribute('aria-pressed', String(!hidden));
  }

  /* -------------------------------------------------------------- listeners */

  modePostButton.addEventListener('click', () => setComposerMode('post'));
  modeReceiptButton.addEventListener('click', () => setComposerMode('receipt'));

  filterAll.addEventListener('click', () => setFeedFilter('all'));
  filter2Hop.addEventListener('click', () => setFeedFilter('2hop'));
  filterPow.addEventListener('click', () => setFeedFilter('pow'));

  importVideoButton.addEventListener('click', () => videoFileInput.click());
  videoFileInput.addEventListener('change', () => {
    void handleVideoFile();
  });
  clearVideoButton.addEventListener('click', clearPendingVideo);

  commandForm.addEventListener('submit', (event) => {
    event.preventDefault();
    const command = commandInput.value;
    commandInput.value = '';
    runCommand(command);
  });

  commandInput.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowUp') {
      if (commandHistory.length === 0) return;
      event.preventDefault();
      commandCursor =
        commandCursor < 0 ? commandHistory.length - 1 : Math.max(0, commandCursor - 1);
      commandInput.value = commandHistory[commandCursor] ?? '';
      return;
    }
    if (event.key === 'ArrowDown') {
      if (commandHistory.length === 0) return;
      event.preventDefault();
      commandCursor =
        commandCursor < 0 ? -1 : Math.min(commandHistory.length - 1, commandCursor + 1);
      commandInput.value = commandCursor < 0 ? '' : (commandHistory[commandCursor] ?? '');
      return;
    }
    if (event.key === 'Escape') {
      commandInput.value = '';
      commandCursor = -1;
    }
  });

  toggleAdvancedButton.addEventListener('click', () => {
    setDiagnosticsHidden(!appShell.classList.contains('diagnostics-hidden'));
  });

  openGuideButton.addEventListener('click', () => openGuide(0));
  closeGuideButton.addEventListener('click', closeGuide);
  guidePrevButton.addEventListener('click', () => {
    if (guideStep === 0) return;
    guideStep -= 1;
    renderGuide();
  });
  guideNextButton.addEventListener('click', () => {
    if (guideStep >= GUIDE_STEPS.length - 1) {
      closeGuide();
      commandInput.focus();
      return;
    }
    guideStep += 1;
    renderGuide();
  });
  guideDoneButton.addEventListener('click', () => {
    closeGuide();
    commandInput.focus();
  });
  guideModal.addEventListener('close', clearGuideTarget);
  guideModal.addEventListener('keydown', (event) => {
    if (event.key === 'ArrowRight') {
      event.preventDefault();
      if (guideStep < GUIDE_STEPS.length - 1) {
        guideStep += 1;
        renderGuide();
      }
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault();
      if (guideStep > 0) {
        guideStep -= 1;
        renderGuide();
      }
    }
  });

  vouchPubkeyButton.addEventListener('click', () => handleManualTrust('vouch'));
  mutePubkeyButton.addEventListener('click', () => handleManualTrust('mute'));

  powSlider.addEventListener('input', renderPowLabel);
  sealButton.addEventListener('click', handleSeal);
  cancelButton.addEventListener('click', () => {
    miningController?.abort();
  });

  receiptSourceInput.addEventListener('input', () => {
    if (receiptBytes !== null) return;
    const text = receiptSourceInput.value;
    receiptDigest = text.trim().length > 0 ? hashMediaText(text) : '';
    updateReceiptDigest();
  });
  receiptFileInput.addEventListener('change', () => {
    void handleReceiptFile();
  });
  receiptClearButton.addEventListener('click', clearReceiptSource);

  openIdentityButton.addEventListener('click', () => openDialog(identityModal));
  closeIdentityButton.addEventListener('click', () => closeDialog(identityModal));
  openManualButton.addEventListener('click', () => openDialog(manualBox));
  closeManualButton.addEventListener('click', () => closeDialog(manualBox));

  copyPubkeyButton.addEventListener('click', () => {
    void copyText(identity.publicKey, identityStatus);
  });

  rotateButton.addEventListener('click', () => {
    miningController?.abort();
    identity = generateIdentity();
    lastPacketJson = '';
    packetResult.hidden = true;
    renderIdentity();
    rebuildTrust();
    renderFeed();
    renderStoreStatus();
    setStatus(identityStatus, 'rotated to a fresh ephemeral identity', 'ok');
  });

  exportQuineButton.addEventListener('click', handleExportQuine);
  importStegoButton.addEventListener('click', () => stegoFileInput.click());
  stegoFileInput.addEventListener('change', () => {
    void handleStegoImport();
  });

  attackTamperButton.addEventListener('click', () => {
    void attackTamperedSignature();
  });
  attackSybilButton.addEventListener('click', () => {
    void attackSybilSpam();
  });
  attackStemButton.addEventListener('click', () => {
    void attackStemHop();
  });

  meshConnectButton.addEventListener('click', () => {
    if (swarm.isJoined) return;
    const topics = parseTopicChannels(topicsInput.value);
    const result = swarm.join(topics);
    renderMesh();
    if (!swarm.isJoined) {
      setStatus(meshNote, 'no signaling transports could be started', 'error');
      return;
    }
    setStatus(
      meshNote,
      `joined ${result.rooms.length} rooms on ${result.relays} relays · discovering peers…`,
      'busy',
    );
  });

  meshDisconnectButton.addEventListener('click', () => {
    meshDisconnectButton.disabled = true;
    void swarm
      .leaveSignaling()
      .catch((error: unknown) => setStatus(meshNote, errorMessage(error), 'error'))
      .finally(() => renderMesh());
  });

  manualOfferButton.addEventListener('click', () => {
    void runManualAction('creating invite · gathering ICE candidates…', async () => {
      const code = await swarm.createManualOffer();
      manualCode.value = code;
      setStatus(
        manualStatus,
        `invite ready · ${code.length} chars — send it to your peer, then paste their answer ` +
          'and press apply answer',
        'ok',
      );
    });
  });

  manualAcceptButton.addEventListener('click', () => {
    void runManualAction('accepting invite · gathering ICE candidates…', async () => {
      const code = manualCode.value.trim();
      if (code.length === 0) throw new Error('paste an invite code first');
      const answer = await swarm.acceptManualOffer(code);
      manualCode.value = answer;
      setStatus(
        manualStatus,
        `answer ready · ${answer.length} chars — send it back; the inviter applies it`,
        'ok',
      );
    });
  });

  manualAnswerButton.addEventListener('click', () => {
    void runManualAction('applying answer…', async () => {
      const code = manualCode.value.trim();
      if (code.length === 0) throw new Error('paste the answer code first');
      await swarm.applyManualAnswer(code);
      setStatus(manualStatus, 'answer applied · waiting for the direct channel…', 'busy');
    });
  });

  manualCopyButton.addEventListener('click', () => {
    if (manualCode.value.trim().length === 0) {
      setStatus(manualStatus, 'no code to copy yet', 'error');
      return;
    }
    void copyText(manualCode.value.trim(), manualStatus);
  });

  telemetryClearButton.addEventListener('click', () => {
    telemetry.clear();
    logEntries.length = 0;
    renderLog();
  });

  encryptButton.addEventListener('click', () => {
    void handleEncrypt();
  });

  restoreToggle.addEventListener('click', () => {
    const showing = !restoreBox.hidden;
    restoreBox.hidden = showing;
    restoreToggle.textContent = showing ? 'restore…' : 'hide restore';
    if (!showing) restorePass.focus();
  });

  restoreButton.addEventListener('click', () => {
    void handleRestore();
  });

  copyPacketButton.addEventListener('click', () => {
    if (lastPacketJson.length === 0) {
      setStatus(mineStatus, 'no packet to copy yet', 'error');
      return;
    }
    void copyText(lastPacketJson, mineStatus);
  });

  /* --------------------------------------------------------------- bootstrap */

  renderIdentity();
  renderPowLabel();
  renderStoreStatus();
  renderFeed();
  renderMesh();
  renderLog();
  updateReceiptDigest();

  void (async (): Promise<void> => {
    setStatus(feedStatus, 'rehydrating storage…', 'busy');
    try {
      const report = await store.load();
      registerStoredMedia();
      rebuildTrust();
      renderFeed();
      renderStoreStatus(report);
      setStatus(
        feedStatus,
        report.errors.length > 0
          ? `loaded ${store.size} packets with ${report.errors.length} storage warning(s)`
          : `loaded ${store.size} packets · ${BACKEND_LABELS[report.backend]}` +
              (report.seed > 0 ? ` · ${report.seed} verified from quine seed` : ''),
        report.errors.length > 0 ? 'error' : 'ok',
      );
      if (store.status.pending) void store.flush().then(() => renderStoreStatus());
    } catch (error) {
      renderFeed();
      renderStoreStatus();
      setStatus(feedStatus, `storage degraded: ${errorMessage(error)}`, 'error');
    }
  })();
}

try {
  boot();
} catch (error) {
  const app = document.getElementById('app');
  const message = document.createElement('p');
  message.className = 'status';
  message.dataset['tone'] = 'error';
  message.textContent = `SPORE failed to start: ${errorMessage(error)}`;
  if (app === null) {
    document.body.append(message);
  } else {
    app.replaceChildren(message);
  }
}
