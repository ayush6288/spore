<div align="center">

# 🧬 SPORE

### Self-Propagating Overlay for Resilient Expression
**No origin server to seize. No app-store listing to remove. No account to suspend.**

[![License: MIT](https://img.shields.io/badge/License-MIT-00F59B)](LICENSE)
![Build: single-file HTML](https://img.shields.io/badge/Build-Single--file_HTML-090D16)
![Crypto: secp256k1 Schnorr + Hashcash](https://img.shields.io/badge/Crypto-secp256k1_Schnorr_%2B_Hashcash-FFB800)
![Transport: WebRTC + RGB LSB stego](https://img.shields.io/badge/Transport-WebRTC_%2B_RGB_LSB_Stego-FF3B5C)

</div>

---

## What is SPORE?

SPORE is a local-first, peer-to-peer publishing protocol and client that compiles into **one self-contained HTML file**. The current verified build is **273,621 bytes (~274 KB raw)**. There is no account server, database, CDN, or required origin. Authors generate keys locally, sign packets locally, and readers verify them locally. Copies move as ordinary files, PNG carriers, or self-replicating HTML snapshots.

The application makes **zero network requests at boot** and works from `file://`. Live peer discovery is optional: it starts only when you press **join**. SPORE then signals over BitTorrent WebSocket trackers and Nostr relays, and carries peer traffic over WebRTC DataChannels (DTLS-encrypted by the browser). If those are blocked, a **Manual Offline SDP Copy-Paste Bridge** can exchange a compressed `spore-peer://…` invite over any messenger.

**SPORE is not encrypted messaging, an anonymity network, or a guarantee of availability.** Packets are public and signed; Dandelion++-style routing is source obfuscation, not anonymity; WebRTC peers may learn your IP address. The threat model below is explicit about what the system does and does not protect.

---

## Guide for Everyday Users

You do not need an account, phone number, email address, or app-store install to read or share SPORE.

### 1. Open SPORE

1. Obtain the built file (`dist/index.html`) by building it yourself or receiving a copy from a trusted mirror. You can rename it to `spore.html`; the filename is not significant.
2. Open it in a current Chromium-based browser, Firefox, or Safari. `file://` works, though some mobile WebViews restrict local files, IndexedDB, WebRTC, or downloads.
3. SPORE boots offline and reads its local packet store and any embedded Quine seed. It does **not** join the network automatically.
4. To go online, enter a channel and press **join** (see below).

Feed filters are **All Verified**, **2-Hop Trusted Only**, and **High PoW Only** (16+ declared bits). Muted authors and under-floor strangers are hidden; verified packets embedded in a Quine seed carry a `SEED` tag.

> The automated end-to-end suite runs in Chromium. Other current browsers are expected to work but are not covered by the automated E2E.

### 2. Unlock a post from a stego carrier

When a creator shares a **SPORE Carrier Image (`.png`)**:

1. Save the `.png` as a file or document. In WhatsApp or Telegram, send/download it as a **Document/File** so the platform does not recompress it.
2. Open your local SPORE copy.
3. Press **Import Stego PNG** in the top bar and select the image.
4. SPORE reads the RGB least-significant bits, checks the frame length and CRC32, decompresses the bundle, and verifies every packet's id, proof of work, and Schnorr signature before merging valid packets.
5. The post appears in the feed.

A carrier is **not encryption**: anyone can decode it. Lossy re-encoding destroys the payload.

### 3. Join the live mesh (optional)

1. Enter a channel/room such as `global + poetry, berlin` and press **join**.
2. SPORE joins the global room plus normalized topic rooms over both BitTorrent WebSocket trackers and Nostr relays.
3. Peers reconcile missing packets with a bounded inventory/request/response sync. New packets use Dandelion++-style stem/fluff routing unless you turn the toggle off.
4. Press **leave** to stop signaling. Manual direct peers stay connected.
5. If public signaling is blocked, press **Open WebRTC peer bridge** to use the Manual Offline SDP Copy-Paste Bridge. Press **create invite**, send the `spore-peer://…` code over any messenger; the other side pastes it and presses **accept invite**, then returns the answer code; the inviter pastes that answer and presses **apply answer**.

Public relays and trackers see connection metadata and IP addresses. Direct WebRTC peers may also learn your IP through ICE. Use a VPN/Tor, the manual bridge, or offline transfer when network-level anonymity matters. SPORE ships no TURN service, so symmetric NAT can prevent a direct connection.

### 4. Export a self-replicating Quine

1. Press **Export Self-Replicating Quine (.html)** in the top bar.
2. The browser downloads `spore-snapshot-<timestamp>.html`.
3. The exported document contains the application plus **up to 200 verified packets**, selected by trust, declared work, and recency. It is not necessarily the entire local store.
4. Send the file over messaging, AirDrop, Nearby Share, Bluetooth, USB, or any file-sharing channel. When opened—even completely offline—it hydrates the same verified feed with no server.

---

## Guide for Creators, Journalists, and Activists

SPORE gives you a local cryptographic identity. It does not hide your network location by itself, and it does not make public posts confidential.

### 1. Identity and encrypted backup

- Each page load generates a fresh secp256k1/BIP340 keypair **in memory**. The Identity panel labels it **ephemeral**; the private key is not persisted automatically across reloads.
- The public fingerprint appears as `spore:0x…`; the full public key can be copied from the Identity panel.
- To keep an identity across sessions, open **key vault**, enter a backup passphrase, press **encrypt key**, and copy the encrypted backup JSON. The private key is never displayed or exported raw.
- To restore, open **key vault**, press **restore…**, paste the backup JSON and passphrase, then press **decrypt & adopt key**.
- Backup encryption is PBKDF2-HMAC-SHA256 (210,000 rounds) → XChaCha20-Poly1305. The passphrase never leaves the tab.
- If you close the tab without a backup, the key is lost. **rotate** replaces the current identity; the old one is recoverable only from a backup.
- The packet store persists through IndexedDB/localStorage, but the identity—and therefore the local trust root—does not. Restore your backup after a reload if you need to keep posting as the same author.

### 2. Publish a post

1. In the **Transmit** composer, choose **Standard Post**.
2. Write the content.
3. Choose proof of work from 8 to 20 bits. The default is **16 bits** (about 65,536 hashes on average); higher values take longer.
4. Keep **Dandelion++ Stem Routing** checked to enter the stem phase, or uncheck it to broadcast directly (direct fluff).
5. Press **mine & seal post**. SPORE mines the nonce, signs the packet, verifies it locally, stores it, and—if the mesh is joined—routes it to peers.
6. Mining time varies by device and target. The progress bar and **cancel** button remain available.

If you are offline, the packet is still stored locally. Export a Quine or a PNG carrier to move it to another device.

### 3. Create a Hydra censorship receipt

Use a receipt to commit to an external post **before** it is removed or geo-blocked.

1. Switch the composer to **Hydra Censorship Receipt**.
2. Paste an Instagram, YouTube, or X/Twitter post URL. Other platforms are rejected by the current validator.
3. Paste the original text **or** choose the original media file (up to 64 MiB). SPORE computes the SHA-256 digest. An optional note is limited to 280 characters.
4. Press **mine & seal receipt**.

The signed receipt commits to the canonical URL, platform post id, source SHA-256, source kind (`media` or `text`), and the commit timestamp. It proves the author held that exact source material at commit time. It does **not** detect a later takedown, timestamp the takedown, or query the platform; the proof is prior possession, not a platform-certified deletion record.

### 4. Distribute as a PNG carrier

1. On any feed card, press **Pack into Stego PNG**.
2. SPORE renders a branded 1080×1080 lossless PNG (growing up to 4096×4096 if needed) and embeds the framed packet bundle in the RGB least-significant bits. No payload bits are written to alpha; the exporter forces opaque alpha so canvas compositing cannot disturb the RGB LSBs.
3. Share the `.png` as a file. The recipient imports it with **Import Stego PNG**.
4. The carrier is not encryption, and the current UI does not expose an arbitrary cover-image picker; it exports a generated SPORE card. Recompression by a platform can destroy the payload.

At 1080×1080, the raw RGB LSB capacity is about 427 KiB; the encoder grows the canvas automatically until the compressed frame fits.

---

## Threat Model

SPORE assumes a hostile network, unreliable hosting, and platforms that may remove content without notice. It protects **authorship integrity, local availability of already-distributed copies, and source obfuscation**. It does **not** provide content confidentiality, strong anonymity against a global observer, or immunity to platform moderation.

| Threat | Why centralized systems fail | SPORE counter | Residual risk |
|---|---|---|---|
| **DNS / SNI blocking and HTTP 451** | Resolvers and middleboxes can block a domain or drop traffic in milliseconds. | The application, cryptography, feed, stego decoder, and Quine hydration work with no network. There is no required origin. Live discovery uses BitTorrent WebSocket trackers, Nostr relays, and a Manual Offline SDP Copy-Paste Bridge. | A total egress block prevents live discovery. Mirrors can still be blocked. There is no domain fronting or built-in covert channel; offline carriers still work. |
| **App-store and platform takedowns** | Stores can remove apps on legal request; platforms can delete posts or accounts. | SPORE is not an app-store listing. It is a single HTML document that can be mirrored, emailed, carried on USB, or sent over a messenger. Quines embed verified packets; PNG carriers embed signed packets; Hydra receipts commit before removal. | File sharing can be blocked, browsers/OSes can restrict local files, and a particular mirror can disappear. There is no automatic update channel unless you distribute a new file. |
| **Signaling choke points** | Blocking one API endpoint or tracker kills a standard WebRTC app. | Two independent Trystero strategies run simultaneously: BitTorrent WebSocket trackers and Nostr relays, each with multiple endpoints. The Manual Offline SDP Copy-Paste Bridge (`spore-peer://…`) needs no tracker or STUN server. | All public relays/trackers can be blocked. The manual bridge needs some reachable path and does not traverse NAT without a direct path. Signaling metadata and direct-peer IPs remain visible. |
| **First-seeder IP harvesting** | An observer monitoring a DHT or relay can log the first address that announces a controversial packet. | Locally authored packets enter a Dandelion++-style **stem** at `hop_count: 0` and go 1-to-1 to one randomly selected peer over a DTLS-encrypted WebRTC DataChannel. `hop_count` advances toward the 3-hop limit; each hop fluffs with 30% probability, when no stem peers remain, or at hop 3. Fluff then broadcasts to all peers except the sender. Duplicate ids are dropped. | WebRTC's DTLS encryption protects transit, not source anonymity, and SPORE adds no custom application-layer payload encryption. A direct WebRTC peer can learn your IP through ICE; a global observer can correlate traffic. Use a VPN/Tor, the manual bridge, or offline transfer when that matters. |
| **Sybil and spam floods** | Open P2P networks without central moderators can be flooded with cheap identities. | Every ingress checks schema, packet id, and Schnorr signature, and confirms the digest meets its declared PoW. Unknown authors need a **16-bit** Hashcash floor to appear in the live feed. The 2-hop Web-of-Trust ranks known authors above strangers; mutes are absorbing; storage is bounded and deterministically evicted. | SHA-256 PoW is commodity work, not memory-hard. A funded adversary can buy cycles. Trust is local and subjective, not global consensus. Verified packets carried in an embedded Quine seed are shown with a `SEED` tag even if they fall below the local unknown-author floor. |
| **Total internet blackouts** | Regional shutdowns sever WebSockets, STUN, and live signaling. | The HTML Quine and PNG carriers work entirely offline. The DOM embeds an LZ-compressed **packet set** inside `<script id="spore-quine-state">`, and local storage cascades IndexedDB → localStorage → memory. | There is no live sync during a blackout; transfer is physical (Bluetooth, Nearby Share, USB, etc.). Device seizure and carrier recompression remain risks. |

### What SPORE does not protect

- **Confidentiality.** Packets are public. Anyone with the file, carrier, or Quine can read them.
- **Strong anonymity.** Dandelion++-style routing reduces trivial source identification; it does not hide IP addresses from direct peers or a global network observer.
- **Availability.** A mirror, relay, or platform can still block or delete a copy.
- **Global moderation or consensus.** The Web-of-Trust is a local policy choice, not a global reputation system.
- **Key persistence.** The identity is ephemeral unless you create and restore an encrypted backup.
- **External audit.** This is a working prototype; the cryptography and protocol have not been independently audited.

---

## Subsystem Architecture and Threat Counters

### secp256k1 Schnorr — authorship and integrity

- Identities are generated locally. Public keys are 32-byte x-only BIP340 keys, compatible with Nostr/NIP-01 conventions.
- A packet id is SHA-256 over a canonical `[0, pubkey, created_at, kind, content, media_cid, reply_to, pow_nonce, pow_bits]` tuple. The Schnorr signature covers the raw 32-byte id.
- Verification needs only the packet and the public key—no CA, DNS, account server, or trusted host.
- `hop_count` and `dandelion_phase` are transport metadata and are excluded from the signed id, so relays can mutate routing state without invalidating authorship.
- Keys can be backed up with PBKDF2-HMAC-SHA256 (210,000 rounds) and XChaCha20-Poly1305; the passphrase never leaves the tab.

**Counters:** forged posts, tampered receipts, impersonation, and server-side content substitution.

### Hashcash-style PoW — Sybil and spam friction

- Each packet id must have at least its declared number of leading zero bits in its SHA-256 digest, checked against the actual digest.
- Default post work is **16 bits** (about 65,536 hashes on average); trust packets use **12 bits**; the UI exposes 8–20 bits.
- Mining is sliced into short macrotasks with progress and cancellation, so a high-bit packet does not freeze the tab.
- Verification happens at the network boundary and again at storage ingress.
- Unknown authors need 16 bits to appear in the live feed. This is a local feed policy, not a global consensus rule.

**Counters:** bulk key generation and low-effort spam. This is deliberate friction, not a consensus mechanism; it raises the cost of a flood without pretending to make one impossible.

### 2-Hop Web-of-Trust — local Sybil filtering

- Trust commands are ordinary signed `kind: 'trust'` packets: `follow:<pubkey>`, `vouch:<pubkey>`, or `mute:<pubkey>`.
- Scores: self `1.0`, direct follow/vouch `0.8`, second-hop vouch `0.4`, unknown `0.1`, muted `0.0`.
- Only an explicit **vouch** from a direct peer creates a second-hop relationship; follow chains cannot launder trust indefinitely.
- Unknown authors are admitted to the live feed at or above the 16-bit PoW floor. Mutes are absorbing, and mutes published by direct peers are honored by default.
- The feed is ordered deterministically by trust, then recency, then id; the store uses the same score for deterministic eviction.
- Verified packets embedded in a Quine seed are displayed with a `SEED` tag, even when they are below the local unknown-author floor.

**Counters:** Sybil floods, reputation laundering, and unwanted authors. Trust remains a local policy choice, not a global reputation system.

### Dandelion++-style routing — source obfuscation

- A locally authored packet enters the **stem** phase at `hop_count: 0` and is forwarded 1-to-1 to exactly one randomly selected peer over a DTLS-encrypted WebRTC DataChannel.
- `hop_count` runs from `0` to `3` (`hop_count: 0..3`), the maximum stem depth. At each hop the packet fluffs with 30% probability, when no stem peers remain, or at the 3-hop limit. Fluff packets are broadcast to all peers except the sender.
- Duplicate packet ids are dropped, and a stem node never forwards back to the peer it received from.
- The UI can bypass stem routing with **direct fluff** when latency matters more than source obfuscation.
- **Transport encryption only:** WebRTC DataChannels are DTLS-encrypted by the browser, but SPORE adds no custom application-layer payload encryption. Dandelion++-style routing is source obfuscation, not an anonymity network.

**Counters:** trivial source identification and targeted blocking of the first publisher. It is source obfuscation, not strong anonymity.

### RGB LSB stego PNG — takedown-resistant carriers

- A packet bundle is serialized as UTF-8 JSON, LZ-compressed, and framed as:

  ```text
  "SPOR" | uint32 payload length | uint32 CRC32 | compressed payload
  ```

- The frame is written only into the **red, green, and blue** least-significant bits. No payload bits are stored in alpha; the exporter forces opaque alpha so canvas premultiplication cannot disturb the payload.
- The default carrier is 1080×1080 (roughly 427 KiB of raw RGB LSB capacity) and grows automatically up to 4096×4096 if needed.
- Export is a lossless PNG. Import validates magic, length, CRC32, decompression, bundle shape, and every packet's signature/PoW before merging.
- A corrupt carrier is rejected with a CRC error; a valid carrier with a tampered packet keeps only the packets that verify.

**Counters:** URL takedowns and image-based redistribution. The image is the carrier, but it is **not encryption**—anyone can decode it, and lossy re-encoding destroys the payload.

### HTML Quine — self-replicating snapshots

- Export clones the running application, strips transient session state (including key displays, passphrases, and backup JSON), and injects a compressed packet set into `<script id="spore-quine-state" type="application/json">`.
- The payload is `lz-string` Base64, whose alphabet cannot contain `</script`, and packets are sorted canonically by id so identical packet sets encode deterministically.
- Export selects up to **200 verified packets**, ordered by trust, declared work, recency, and id. It is a selected snapshot, not necessarily the whole store.
- On boot, storage reads the seed, decompresses it, verifies every packet, and drops invalid entries. Valid packets hydrate the feed with no network access.
- Persistence cascades IndexedDB → localStorage → in-memory state, while the embedded Quine seed is merged and verified at boot. `file://` and locked-down WebViews therefore remain usable.
- The store is a content-addressed packet set with CRDT-style merge semantics and deterministic eviction. The Quine embeds a packet set, not a private key or a full CRDT state dump.

**Counters:** hosting takedowns, DNS blocking, and link rot. A Quine is a complete, portable copy of the app plus its selected public packet set.

### Bounded anti-entropy sync

- On peer join and every 45 seconds, peers exchange a bounded inventory of packet ids.
- The receiver requests only missing ids; the responder sends those packets, and every packet is verified again before storage.
- Sync sessions have TTLs and concurrency caps; invalid, duplicate, or oversized messages are dropped.

**Counters:** partition repair and partial-store convergence without flooding the full set.

---

## Phase 6 — Build, Verification, and Single-File Audit

Requires a current Node.js LTS release.

### Build and verify

```sh
npm ci
npm run verify          # typecheck + unit/integration tests + production build
```

`npm run build` alone produces the shippable artifact:

```text
dist/index.html
```

The Vite + `vite-plugin-singlefile` pipeline inlines the JavaScript and CSS. `dist/` contains no separate assets, and the built page makes **zero network requests at boot**.

### Verified artifact

At the time of writing:

```text
size:     273,621 bytes (~274 KB raw)
sha256:   5513b4e2b09d40e03d47cf27f2e0a356f7131e51e5f89931f250d737eaa33cdf
tests:    105 passed across 6 files
typecheck: clean
```

The size and hash change whenever the source changes; re-run the audit for your own build.

### Single-file audit

```sh
# Must print exactly one match, the embedded Quine seed slot.
grep -c 'id="spore-quine-state"' dist/index.html

# Must print nothing: no external scripts, stylesheets, images, or iframes.
grep -nE '<script[^>]+src=|<link[^>]+rel="stylesheet"|<img[^>]+src=|<iframe' dist/index.html || true

# The artifact should be the only file in dist/.
find dist -maxdepth 1 -type f

# Record the exact bytes you are distributing.
wc -c dist/index.html
shasum -a 256 dist/index.html
```

The source template (`index.html`) contains `<script id="spore-quine-state" type="application/json"></script>` before the module entry. Exported Quines replace its contents with a compressed packet set; the built application reads that element at boot. Keeping the slot in the template makes Quine hydration deterministic on `file://`.

### Distribute

1. Build and audit the artifact:
   ```sh
   npm run verify
   shasum -a 256 dist/index.html
   ```
2. Copy `dist/index.html` anywhere. Rename it to `spore.html` if that helps recipients; the filename is not significant.
3. Open it directly with `file://`, or serve it from any static host. No server-side runtime, rewrite rules, or MIME map is required.
4. Share it over messaging, email, USB, a LAN share, IPFS, or any web host. Recipients need only a browser.
5. For offline propagation, use **Pack into Stego PNG** on a feed item or **Export Self-Replicating Quine** to produce carriers that already contain verified packets.
6. Live mesh is optional. Joining uses BitTorrent WebSocket trackers, Nostr relays, and the Manual Offline SDP Copy-Paste Bridge if those are blocked. Use **Open WebRTC peer bridge** with a `spore-peer://` exchange, or distribute a Quine/PNG instead.

### Operational notes

- The build is a single file, but it is still executable HTML. Host it with `Content-Type: text/html` and avoid intermediaries that rewrite or minify the document.
- Some browsers restrict IndexedDB or localStorage on `file://`; SPORE falls back to memory and the embedded seed rather than failing.
- The identity is in-memory and ephemeral. Back it up from **Key Vault** before relying on it, and restore after reload. **rotate** discards the old identity unless it was backed up.
- Live signaling and WebRTC expose metadata and possibly IP addresses. There is no TURN service, so symmetric NAT may block direct connections.
- Verify packets, not screenshots. A carrier or Quine is only as trustworthy as the signatures inside it.
- This is a prototype, not an independently audited security product.

---

## License

MIT. See [LICENSE](LICENSE).
