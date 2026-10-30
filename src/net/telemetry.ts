/**
 * SPORE telemetry bus.
 *
 * The mesh, gossip and Dandelion layers emit a small, fixed vocabulary of
 * events. The UI inspector subscribes to this bus; nothing here touches the
 * network. History is bounded so a long-lived tab cannot grow without limit.
 */

export const TELEMETRY_EVENTS = [
  'peer:join',
  'peer:leave',
  'pkt:stem',
  'pkt:fluff',
  'pkt:drop',
  'sync:complete',
] as const;

export type TelemetryEventName = (typeof TELEMETRY_EVENTS)[number];

export type TelemetryData = Readonly<Record<string, string | number | boolean | null>>;

export interface TelemetryEvent {
  readonly seq: number;
  readonly at: number;
  readonly name: TelemetryEventName;
  readonly data: TelemetryData;
}

export type TelemetryListener = (event: TelemetryEvent) => void;

export interface TelemetryOptions {
  /** Maximum retained events. Default 240. */
  readonly maxHistory?: number;
  readonly now?: () => number;
}

export const DEFAULT_TELEMETRY_HISTORY = 240;

function assertEventName(name: string): asserts name is TelemetryEventName {
  if (!(TELEMETRY_EVENTS as readonly string[]).includes(name)) {
    throw new TypeError(`Unknown telemetry event: ${name}`);
  }
}

export class Telemetry {
  private readonly maxHistory: number;
  private readonly now: () => number;
  private readonly history: TelemetryEvent[] = [];
  private readonly listeners = new Set<TelemetryListener>();
  private seq = 0;

  constructor(options: TelemetryOptions = {}) {
    this.maxHistory = options.maxHistory ?? DEFAULT_TELEMETRY_HISTORY;
    if (!Number.isSafeInteger(this.maxHistory) || this.maxHistory < 1) {
      throw new RangeError('Telemetry maxHistory must be a positive integer');
    }
    this.now = options.now ?? Date.now;
  }

  emit(name: TelemetryEventName, data: TelemetryData = {}): TelemetryEvent {
    assertEventName(name);
    const event: TelemetryEvent = Object.freeze({
      seq: ++this.seq,
      at: this.now(),
      name,
      data: Object.freeze({ ...data }),
    });
    this.history.push(event);
    if (this.history.length > this.maxHistory) {
      this.history.splice(0, this.history.length - this.maxHistory);
    }
    for (const listener of this.listeners) {
      try {
        listener(event);
      } catch {
        // An inspector bug must never break routing.
      }
    }
    return event;
  }

  /** Oldest first. */
  snapshot(): readonly TelemetryEvent[] {
    return this.history.slice();
  }

  subscribe(listener: TelemetryListener): () => void {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  }

  clear(): void {
    this.history.length = 0;
  }
}
