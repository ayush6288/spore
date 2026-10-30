/**
 * SPORE identity: secp256k1 + BIP340 Schnorr (Nostr/NIP-01 compatible).
 *
 * Keys are 32-byte hex strings. The public key is x-only (32 bytes), matching
 * NIP-01. All primitives are pure JavaScript from @noble so identities work
 * identically under https://, file:// and content:// — no WebCrypto.
 */

import { schnorr } from '@noble/curves/secp256k1';
import { pbkdf2 } from '@noble/hashes/pbkdf2';
import { sha256 } from '@noble/hashes/sha256';
import { randomBytes } from '@noble/hashes/utils';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';
import { assertHex, bytesToHex, hexToBytes, isHex, utf8ToBytes } from './encoding';

/** Order of the secp256k1 group. Valid secret keys are in [1, n - 1]. */
const SECP256K1_ORDER = BigInt(
  '0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141',
);

export const PRIVATE_KEY_BYTES = 32;
export const PUBLIC_KEY_BYTES = 32;
export const SIGNATURE_BYTES = 64;

export const DEFAULT_KDF_ITERATIONS = 210_000;
export const MIN_KDF_ITERATIONS = 10_000;
export const MAX_KDF_ITERATIONS = 1_000_000;

const BACKUP_VERSION = 1;
const BACKUP_KDF = 'pbkdf2-sha256';
const BACKUP_SALT_BYTES = 16;
const BACKUP_NONCE_BYTES = 24;
const BACKUP_CIPHERTEXT_BYTES = PRIVATE_KEY_BYTES + 16; // XChaCha20-Poly1305 tag
const MAX_BACKUP_JSON_CHARS = 8_192;
const MAX_PASSPHRASE_CHARS = 1_024;

/**
 * A local identity. `privateKey` is sensitive: never publish it, never log it,
 * and only place it in storage after passphrase encryption.
 */
export interface SporeIdentity {
  /** 64 lowercase hex chars (32 bytes). */
  readonly privateKey: string;
  /** 64 lowercase hex chars (32-byte x-only Schnorr public key). */
  readonly publicKey: string;
  /** Human-readable short fingerprint, e.g. `spore:0x8f3a1c9b7e2d`. */
  readonly fingerprint: string;
}

export interface EncryptedKeyBackup {
  readonly v: 1;
  readonly kdf: 'pbkdf2-sha256';
  readonly iterations: number;
  /** 16-byte salt, hex. */
  readonly salt: string;
  /** 24-byte XChaCha20-Poly1305 nonce, hex. */
  readonly nonce: string;
  /** 48-byte ciphertext (32-byte key + 16-byte Poly1305 tag), hex. */
  readonly ciphertext: string;
  readonly pubkey: string;
  readonly fingerprint: string;
  readonly created_at: number;
}

export interface EncryptIdentityOptions {
  readonly iterations?: number;
  readonly salt?: Uint8Array;
  readonly nonce?: Uint8Array;
  readonly createdAt?: number;
}

function assertPrivateKey(privateKeyHex: string): string {
  const hex = assertHex(privateKeyHex, PRIVATE_KEY_BYTES, 'Private key');
  const scalar = BigInt(`0x${hex}`);
  if (scalar === 0n || scalar >= SECP256K1_ORDER) {
    throw new RangeError('Private key is outside the secp256k1 scalar range');
  }
  return hex;
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase !== 'string' || passphrase.length === 0) {
    throw new TypeError('Passphrase must be a non-empty string');
  }
  if (passphrase.length > MAX_PASSPHRASE_CHARS) {
    throw new RangeError(`Passphrase must be at most ${MAX_PASSPHRASE_CHARS} characters`);
  }
}

export function publicKeyFromPrivateKey(privateKeyHex: string): string {
  const hex = assertPrivateKey(privateKeyHex);
  return bytesToHex(schnorr.getPublicKey(hexToBytes(hex)));
}

/**
 * Derive a short, stable, human-readable fingerprint from an x-only pubkey.
 * Twelve hex chars = 48 bits, enough to disambiguate humans, not a security id.
 */
export function fingerprintOf(publicKey: string, hexChars = 12): string {
  const hex = assertHex(publicKey, PUBLIC_KEY_BYTES, 'Public key');
  if (!Number.isInteger(hexChars) || hexChars < 4 || hexChars > 64 || hexChars % 2 !== 0) {
    throw new RangeError('Fingerprint length must be an even number between 4 and 64 hex chars');
  }
  return `spore:0x${hex.slice(0, hexChars)}`;
}

export function identityFromPrivateKey(privateKeyHex: string): SporeIdentity {
  const privateKey = assertPrivateKey(privateKeyHex);
  const publicKey = publicKeyFromPrivateKey(privateKey);
  return Object.freeze({
    privateKey,
    publicKey,
    fingerprint: fingerprintOf(publicKey),
  });
}

export function generateIdentity(): SporeIdentity {
  const secret = schnorr.utils.randomSecretKey();
  return identityFromPrivateKey(bytesToHex(secret));
}

export function exportPrivateKey(identity: SporeIdentity): string {
  return assertPrivateKey(identity.privateKey);
}

function backupAad(iterations: number, salt: string, pubkey: string): Uint8Array {
  return utf8ToBytes(`spore-key-backup|${BACKUP_VERSION}|${BACKUP_KDF}|${iterations}|${salt}|${pubkey}`);
}

function normalizeIterations(iterations: number): number {
  if (
    !Number.isSafeInteger(iterations) ||
    iterations < MIN_KDF_ITERATIONS ||
    iterations > MAX_KDF_ITERATIONS
  ) {
    throw new RangeError(
      `PBKDF2 iterations must be between ${MIN_KDF_ITERATIONS} and ${MAX_KDF_ITERATIONS}`,
    );
  }
  return iterations;
}

/**
 * Encrypt a private key for backup/sharing with a passphrase.
 * PBKDF2-HMAC-SHA256 → 32-byte key → XChaCha20-Poly1305 (AEAD).
 */
export function encryptIdentity(
  identity: SporeIdentity,
  passphrase: string,
  options: EncryptIdentityOptions = {},
): EncryptedKeyBackup {
  assertPassphrase(passphrase);
  const iterations = normalizeIterations(options.iterations ?? DEFAULT_KDF_ITERATIONS);
  const salt = options.salt ?? randomBytes(BACKUP_SALT_BYTES);
  const nonce = options.nonce ?? randomBytes(BACKUP_NONCE_BYTES);
  if (salt.length !== BACKUP_SALT_BYTES || nonce.length !== BACKUP_NONCE_BYTES) {
    throw new RangeError(`Salt must be ${BACKUP_SALT_BYTES} bytes and nonce ${BACKUP_NONCE_BYTES} bytes`);
  }

  const publicKey = assertHex(identity.publicKey, PUBLIC_KEY_BYTES, 'Public key');
  const privateKey = assertPrivateKey(identity.privateKey);
  const saltHex = bytesToHex(salt);
  const nonceHex = bytesToHex(nonce);

  const derivedKey = pbkdf2(sha256, utf8ToBytes(passphrase), salt, {
    c: iterations,
    dkLen: 32,
  });

  try {
    const cipher = xchacha20poly1305(derivedKey, nonce, backupAad(iterations, saltHex, publicKey));
    const ciphertext = cipher.encrypt(hexToBytes(privateKey));
    return Object.freeze({
      v: BACKUP_VERSION,
      kdf: BACKUP_KDF,
      iterations,
      salt: saltHex,
      nonce: nonceHex,
      ciphertext: bytesToHex(ciphertext),
      pubkey: publicKey,
      fingerprint: fingerprintOf(publicKey),
      created_at: options.createdAt ?? Date.now(),
    });
  } finally {
    derivedKey.fill(0);
  }
}

const BACKUP_KEYS = new Set([
  'v',
  'kdf',
  'iterations',
  'salt',
  'nonce',
  'ciphertext',
  'pubkey',
  'fingerprint',
  'created_at',
]);

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Strictly validate an untrusted backup object (e.g. from JSON). */
export function validateKeyBackup(value: unknown): EncryptedKeyBackup {
  if (!isRecord(value)) throw new TypeError('Key backup must be an object');
  for (const key of Object.keys(value)) {
    if (!BACKUP_KEYS.has(key)) throw new TypeError(`Unknown key backup field: ${key}`);
  }
  if (value['v'] !== BACKUP_VERSION) throw new TypeError('Unsupported key backup version');
  if (value['kdf'] !== BACKUP_KDF) throw new TypeError('Unsupported key backup KDF');

  const iterations = normalizeIterations(value['iterations'] as number);
  const salt = assertHex(value['salt'], BACKUP_SALT_BYTES, 'Backup salt');
  const nonce = assertHex(value['nonce'], BACKUP_NONCE_BYTES, 'Backup nonce');
  const ciphertext = assertHex(value['ciphertext'], BACKUP_CIPHERTEXT_BYTES, 'Backup ciphertext');
  const pubkey = assertHex(value['pubkey'], PUBLIC_KEY_BYTES, 'Backup public key');
  const fingerprint = value['fingerprint'];
  if (typeof fingerprint !== 'string' || fingerprint !== fingerprintOf(pubkey)) {
    throw new TypeError('Backup fingerprint does not match its public key');
  }
  const createdAt = value['created_at'];
  if (typeof createdAt !== 'number' || !Number.isSafeInteger(createdAt) || createdAt < 0) {
    throw new TypeError('Backup created_at must be a non-negative integer');
  }

  return Object.freeze({
    v: BACKUP_VERSION,
    kdf: BACKUP_KDF,
    iterations,
    salt,
    nonce,
    ciphertext,
    pubkey,
    fingerprint,
    created_at: createdAt,
  });
}

export function serializeKeyBackup(backup: EncryptedKeyBackup): string {
  return JSON.stringify(validateKeyBackup(backup));
}

export function parseKeyBackup(json: string): EncryptedKeyBackup {
  if (typeof json !== 'string' || json.length === 0 || json.length > MAX_BACKUP_JSON_CHARS) {
    throw new TypeError('Key backup JSON is empty or too large');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    throw new TypeError('Key backup is not valid JSON');
  }
  return validateKeyBackup(parsed);
}

/** Decrypt and verify a passphrase backup. Wrong passphrases fail closed. */
export function decryptIdentity(backup: EncryptedKeyBackup, passphrase: string): SporeIdentity {
  assertPassphrase(passphrase);
  const validated = validateKeyBackup(backup);
  const derivedKey = pbkdf2(
    sha256,
    utf8ToBytes(passphrase),
    hexToBytes(validated.salt),
    { c: validated.iterations, dkLen: 32 },
  );

  let plaintext: Uint8Array | undefined;
  try {
    const cipher = xchacha20poly1305(
      derivedKey,
      hexToBytes(validated.nonce),
      backupAad(validated.iterations, validated.salt, validated.pubkey),
    );
    plaintext = cipher.decrypt(hexToBytes(validated.ciphertext));
    if (plaintext.length !== PRIVATE_KEY_BYTES) {
      throw new Error('Unexpected key length');
    }
    const identity = identityFromPrivateKey(bytesToHex(plaintext));
    if (identity.publicKey !== validated.pubkey || identity.fingerprint !== validated.fingerprint) {
      throw new Error('Backup public key mismatch');
    }
    return identity;
  } catch {
    throw new Error('Invalid passphrase or corrupted key backup');
  } finally {
    plaintext?.fill(0);
    derivedKey.fill(0);
  }
}

/** A helper for explorers and tests: is this a structurally valid x-only pubkey? */
export function isValidPublicKey(value: unknown): value is string {
  if (!isHex(value, PUBLIC_KEY_BYTES)) return false;
  try {
    schnorr.utils.lift_x(BigInt(`0x${value}`));
    return true;
  } catch {
    return false;
  }
}
