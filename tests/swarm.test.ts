import { describe, expect, it } from 'vitest';
import {
  GLOBAL_ROOM,
  MANUAL_CODE_PREFIX,
  TOPIC_PREFIX,
  decodeManualSignalCode,
  encodeManualSignalCode,
  normalizeTopicChannel,
  parseTopicChannels,
  roomIdsFor,
  type ManualSignalPayload,
} from '../src/net/swarm';

const SDP = 'v=0\r\no=- 4611731400430051336 2 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n';

describe('topic room normalization', () => {
  it('normalizes case, separators, punctuation and the topic prefix', () => {
    expect(normalizeTopicChannel('Poetry')).toBe(`${TOPIC_PREFIX}poetry`);
    expect(normalizeTopicChannel('spore-topic-Berlin')).toBe(`${TOPIC_PREFIX}berlin`);
    expect(normalizeTopicChannel('  field notes!! ')).toBe(`${TOPIC_PREFIX}field-notes`);
    expect(normalizeTopicChannel('a')).toBeNull();
    expect(normalizeTopicChannel('  ...  ')).toBeNull();
    expect(normalizeTopicChannel('x'.repeat(120))).toBe(`${TOPIC_PREFIX}${'x'.repeat(48)}`);
  });

  it('splits, deduplicates and always includes the global room', () => {
    expect(parseTopicChannels('poetry, berlin\nfield-notes, POETRY')).toEqual([
      `${TOPIC_PREFIX}poetry`,
      `${TOPIC_PREFIX}berlin`,
      `${TOPIC_PREFIX}field-notes`,
    ]);
    expect(parseTopicChannels(' , ')).toEqual([]);
    expect(roomIdsFor([], GLOBAL_ROOM)).toEqual([GLOBAL_ROOM]);
    expect(roomIdsFor([`${TOPIC_PREFIX}poetry`, 'poetry', 'spore-global-v1'])).toEqual([
      GLOBAL_ROOM,
      `${TOPIC_PREFIX}poetry`,
    ]);
  });
});

describe('manual SDP codec', () => {
  it('round-trips offers and answers through the spore-peer URI', () => {
    const offer: ManualSignalPayload = {
      v: 1,
      kind: 'offer',
      id: 'offer-123',
      from: 'peer-abcdef',
      sdp: SDP,
    };
    const offerCode = encodeManualSignalCode(offer);
    expect(offerCode.startsWith(MANUAL_CODE_PREFIX)).toBe(true);
    expect(decodeManualSignalCode(offerCode)).toEqual(offer);

    const answer: ManualSignalPayload = {
      v: 1,
      kind: 'answer',
      id: 'offer-123',
      from: 'peer-ghijkl',
      to: 'peer-abcdef',
      sdp: SDP,
    };
    const answerCode = encodeManualSignalCode(answer);
    expect(decodeManualSignalCode(answerCode)).toEqual(answer);
  });

  it('tolerates surrounding whitespace but rejects malformed codes', () => {
    const code = encodeManualSignalCode({
      v: 1,
      kind: 'offer',
      id: 'offer-123',
      from: 'peer-abcdef',
      sdp: SDP,
    });
    expect(decodeManualSignalCode(` \n${code}\n `)).not.toBeNull();
    expect(decodeManualSignalCode('')).toBeNull();
    expect(decodeManualSignalCode('spore-peer://')).toBeNull();
    expect(decodeManualSignalCode('https://example.com')).toBeNull();
    expect(decodeManualSignalCode(`${MANUAL_CODE_PREFIX}not-lz-data`)).toBeNull();
  });

  it('refuses to encode missing targets or invalid identifiers', () => {
    expect(() =>
      encodeManualSignalCode({
        v: 1,
        kind: 'answer',
        id: 'offer-123',
        from: 'peer-abcdef',
        sdp: SDP,
      }),
    ).toThrow(/target/);
    expect(() =>
      encodeManualSignalCode({
        v: 1,
        kind: 'offer',
        id: 'bad id',
        from: 'peer-abcdef',
        sdp: SDP,
      }),
    ).toThrow(/URL-safe/);
    expect(() =>
      encodeManualSignalCode({
        v: 1,
        kind: 'offer',
        id: 'offer-123',
        from: 'peer-abcdef',
        sdp: '',
      }),
    ).toThrow(/SDP/);
  });
});
