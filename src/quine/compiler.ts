/**
 * Self-replicating HTML quine compiler.
 *
 * The exported document is the live SPORE application with every transient
 * runtime artifact reset, plus a compressed packet set embedded in
 * `<script id="spore-quine-state">`. Opening the resulting .html on another
 * device rehydrates the same verified feed with zero network access.
 */

import { verifyPacket, type SporePacket } from '../crypto/packet';
import { QUINE_STATE_ID, encodeQuineState } from './state';

export const DEFAULT_QUINE_PACKETS = 200;

export interface QuineSelectionOptions {
  /** Maximum verified packets embedded in the snapshot. */
  readonly maxPackets?: number;
  /** Injected trust graph for ordering (higher scores survive the cut). */
  readonly trustScore?: (pubkey: string) => number;
}

export interface QuineBuildOptions extends QuineSelectionOptions {
  readonly createdAt?: number;
}

export interface QuineExportOptions extends QuineBuildOptions {
  readonly document?: Document;
  readonly download?: boolean;
  readonly fileName?: string;
  readonly now?: number;
}

export interface BuiltQuine {
  readonly html: string;
  readonly packets: SporePacket[];
}

function scoreOf(trustScore: ((pubkey: string) => number) | undefined, pubkey: string): number {
  if (trustScore === undefined) return 0.1;
  try {
    const score = trustScore(pubkey);
    return Number.isFinite(score) ? score : 0.1;
  } catch {
    return 0.1;
  }
}

/**
 * Deterministically choose the top N *verified* packets. Trust first, then
 * declared work, then recency, then id.
 */
export function selectQuinePackets(
  packets: Iterable<SporePacket>,
  options: QuineSelectionOptions = {},
): SporePacket[] {
  const maxPackets = options.maxPackets ?? DEFAULT_QUINE_PACKETS;
  if (!Number.isSafeInteger(maxPackets) || maxPackets < 1) {
    throw new RangeError('maxPackets must be a positive integer');
  }

  const unique = new Map<string, SporePacket>();
  for (const packet of packets) {
    const result = verifyPacket(packet);
    if (!result.ok) continue;
    if (!unique.has(result.packet.id)) unique.set(result.packet.id, result.packet);
  }

  return [...unique.values()]
    .sort((a, b) => {
      const scoreDelta = scoreOf(options.trustScore, b.pubkey) - scoreOf(options.trustScore, a.pubkey);
      if (scoreDelta !== 0) return scoreDelta;
      if (a.pow_bits !== b.pow_bits) return b.pow_bits - a.pow_bits;
      if (a.created_at !== b.created_at) return b.created_at - a.created_at;
      return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
    })
    .slice(0, maxPackets);
}

function asHtmlElement(node: Element | null): HTMLElement | null {
  return node instanceof HTMLElement ? node : null;
}

function setText(root: ParentNode, selector: string, text: string): void {
  const element = root.querySelector(selector);
  if (element !== null) element.textContent = text;
}

function setHidden(root: ParentNode, selector: string, hidden: boolean): void {
  const element = asHtmlElement(root.querySelector(selector));
  if (element !== null) element.hidden = hidden;
}

function setActive(root: ParentNode, selector: string): void {
  for (const element of root.querySelectorAll(selector)) {
    element.classList.add('is-active');
  }
}

function clearActive(root: ParentNode, selector: string): void {
  for (const element of root.querySelectorAll(selector)) {
    element.classList.remove('is-active');
  }
}

function resetToggle(root: ParentNode, selector: string, checked: boolean): void {
  const input = root.querySelector(selector);
  if (input instanceof HTMLInputElement) {
    input.checked = checked;
    if (checked) input.setAttribute('checked', '');
    else input.removeAttribute('checked');
  }
}


/**
 * Erase everything that is a product of this particular runtime session:
 * generated key displays, status lines, progress, feed nodes, result JSON,
 * passphrase fields and backup blobs.
 */
function stripTransientState(root: HTMLElement): void {
  for (const script of root.querySelectorAll(`script[id="${QUINE_STATE_ID}"]`)) {
    script.remove();
  }

  const feed = root.querySelector('#feed');
  if (feed !== null) feed.replaceChildren();

  for (const textarea of root.querySelectorAll('textarea')) {
    textarea.textContent = '';
    textarea.removeAttribute('value');
  }
  for (const input of root.querySelectorAll(
    'input[type="password"], input[type="text"], input[type="url"], input[type="search"]',
  )) {
    input.removeAttribute('value');
    if (input instanceof HTMLInputElement) input.value = '';
  }
  for (const fileInput of root.querySelectorAll('input[type="file"]')) {
    if (fileInput instanceof HTMLInputElement) fileInput.value = '';
  }

  setText(root, '#fingerprint', 'spore:0x…');
  setText(root, '#pubkey', '…');
  setText(root, '#store-status', 'booting storage…');
  setText(root, '#storage-mode', '…');
  setText(root, '#node-status-text', 'OFFLINE');
  setText(root, '#peers-stat', '0');
  setText(root, '#relays-stat', '0');
  asHtmlElement(root.querySelector('#node-pill'))?.setAttribute('data-state', 'offline');
  asHtmlElement(root.querySelector('#store-status'))?.classList.remove('warn');
  setText(root, '#feed-count', 'loading packets…');
  setText(root, '#mine-status', '');
  setText(root, '#backup-status', '');
  setText(root, '#identity-status', '');
  setText(root, '#trust-status', '');
  setText(root, '#stego-status', '');
  setText(root, '#adversary-status', '');
  setText(root, '#receipt-status', '');
  setText(root, '#receipt-digest', 'not computed');
  setText(root, '#pow-rate', 'idle · 0 h/s');
  setText(root, '#feed-status', '');
  setText(root, '#mesh-status', 'offline · zero requests');
  setText(root, '#mesh-note', '');
  setText(root, '#mesh-summary',
    'Signaling is off until you join. Peers are discovered simultaneously over public ' +
      'Nostr relays and BitTorrent WebSocket trackers, then talk directly over WebRTC.');
  setText(root, '#peer-count', '0');
  setText(root, '#manual-status', '');
  setText(root, '#telemetry-count', '0 events');
  asHtmlElement(root.querySelector('#peer-list'))?.replaceChildren();
  asHtmlElement(root.querySelector('#telemetry-list'))?.replaceChildren();
  const manualBox = asHtmlElement(root.querySelector('#manual-box'));
  manualBox?.removeAttribute('open');
  asHtmlElement(root.querySelector('#identity-modal'))?.removeAttribute('open');
  setText(root, '#verdict', 'verified');
  setText(root, '#result-id', '');
  setText(root, '#result-pow', '');
  setText(root, '#result-time', '');
  setText(root, '#result-sig', '');
  setText(root, '#result-json', '');
  setText(root, '#restore-toggle', 'restore…');
  setText(root, '#seal', 'mine & seal post');

  setHidden(root, '#packet-result', true);
  setHidden(root, '#restore-box', true);
  setHidden(root, '#cancel', true);
  setHidden(root, '#receipt-fields', true);
  setHidden(root, '#post-fields', false);

  clearActive(root, '.filter-button');
  setActive(root, '#filter-all');
  clearActive(root, '.mode-button');
  setActive(root, '#mode-post');
  resetToggle(root, '#dandelion-toggle', true);

  const verdict = asHtmlElement(root.querySelector('#verdict'));
  verdict?.removeAttribute('data-ok');
  for (const element of root.querySelectorAll('[data-tone]')) {
    element.removeAttribute('data-tone');
  }
  // Dynamic titles can carry the live pubkey or storage diagnostics.
  for (const element of root.querySelectorAll('[title]')) {
    element.removeAttribute('title');
  }

  const progress = asHtmlElement(root.querySelector('#progress-bar'));
  if (progress !== null) progress.style.width = '0%';
  const powSlider = asHtmlElement(root.querySelector('#pow-bits')) as HTMLInputElement | null;
  if (powSlider !== null) {
    powSlider.value = '16';
    powSlider.setAttribute('value', '16');
  }
  setText(root, '#pow-output', '16 bits · ~65,536 hashes');

  for (const button of root.querySelectorAll('button')) {
    button.removeAttribute('disabled');
  }
}

/**
 * Clone the live shell, reset transient UI, and inject fresh quine state.
 * The returned HTML is fully self-contained if the source was built by Vite.
 */
export function buildQuineHtml(
  doc: Document,
  packets: Iterable<SporePacket>,
  options: QuineBuildOptions = {},
): BuiltQuine {
  const selected = selectQuinePackets(packets, options);
  const createdAt = options.createdAt ?? Date.now();
  const stateJson = encodeQuineState(selected, { createdAt });

  const root = doc.documentElement.cloneNode(true);
  if (!(root instanceof HTMLElement)) throw new Error('Document has no clonable HTML root');
  stripTransientState(root);

  const body = root.querySelector('body');
  if (body === null) throw new Error('Document has no body');

  const stateScript = doc.createElement('script');
  stateScript.id = QUINE_STATE_ID;
  stateScript.type = 'application/json';
  stateScript.textContent = stateJson;
  body.insertBefore(stateScript, body.firstChild);

  return {
    html: `<!doctype html>\n${root.outerHTML}`,
    packets: selected,
  };
}

function safeFileName(fileName: string): string {
  return fileName.replace(/[/\\?%*:|"<>]/g, '_');
}

function triggerDownload(blob: Blob, fileName: string, doc: Document): void {
  const url = URL.createObjectURL(blob);
  const anchor = doc.createElement('a');
  anchor.href = url;
  anchor.download = fileName;
  anchor.rel = 'noopener';
  anchor.style.display = 'none';
  (doc.body ?? doc.documentElement).append(anchor);
  anchor.click();
  anchor.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30_000);
}

/**
 * Build and download `spore-snapshot-<timestamp>.html`. Returns the Blob even
 * when `download: false` (for tests, share targets and alternative transports).
 */
export function exportSporeQuine(
  packets: Iterable<SporePacket>,
  options: QuineExportOptions = {},
): Blob {
  const doc = options.document ?? (typeof document === 'undefined' ? null : document);
  if (doc === null) throw new Error('exportSporeQuine requires a DOM document');

  const built = buildQuineHtml(doc, packets, options);
  const blob = new Blob([built.html], { type: 'text/html;charset=utf-8' });
  const now = options.now ?? Date.now();
  const fileName = safeFileName(options.fileName ?? `spore-snapshot-${now}.html`);

  if (options.download !== false) triggerDownload(blob, fileName, doc);
  return blob;
}
