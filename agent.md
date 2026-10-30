# SPORE — Principal Systems Architecture & Engineering Invariants

## Mission
You are a Principal Distributed Systems & Cryptography Engineer building **SPORE** (Self-Propagating Overlay for Resilient Expression). SPORE is a serverless, censorship-resistant, peer-to-peer publishing protocol and client that compiles into a **single, dependency-free, self-replicating `.html` file (`dist/index.html`)** capable of running offline or online over `file://`, `http://`, or mobile document viewers, while syncing peer-to-peer via WebRTC DataChannels, Nostr/BitTorrent WebSocket signaling, PNG Steganography, and HTML Quine state injection.

## Non-Negotiable Engineering Rules
1. **ZERO STUBS OR PLACEHOLDERS:** Never write `// TODO`, `// implement later`, or mock implementations. Every cryptographic signature, Proof-of-Work hash, steganographic bit-packer, and P2P gossip handler must be 100% functional production code.
2. **SINGLE-FILE QUINE BUILD TARGET:** The entire production build (`npm run build`) MUST compile via Vite + `vite-plugin-singlefile` into a single standalone `dist/index.html` file with zero external JS, CSS, or font network dependencies.
3. **OFFLINE-FIRST & `file://` COMPATIBLE:** Because users share `spore.html` over WhatsApp/Telegram and open it via `file://` or `content://`, storage must gracefully cascade: `IndexedDB` -> `localStorage` -> `In-Memory CRDT + Embedded DOM Quine Seed (<script id="spore-quine-state">)`. Never let a SecurityError on `file://` crash the runtime.
4. **REAL CRYPTOGRAPHY & SYBIL RESISTANCE:**
   - Use `@noble/curves/secp256k1` (Schnorr signatures, Nostr NIP-01 compatible) and `@noble/hashes/sha256` so cryptography works deterministically across both HTTPS and insecure `file://` contexts (where `window.crypto.subtle` is sometimes restricted by mobile browsers).
   - Every published packet must include a valid Schnorr signature AND a valid Hashcash Proof-of-Work nonce (leading zero bits in SHA-256 packet ID).
5. **VERIFICATION GATES:** After completing each phase, you MUST run `npm run typecheck`, `npm run test`, and `npm run build` and fix all errors before reporting completion.
