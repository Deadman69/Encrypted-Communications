# README\_Technical.md (developer & deep-dive)

## Overview

This repository contains a minimal sealed-sender-style messaging system:

* **Client** (`client/`): Tkinter desktop app; PyNaCl for crypto; optional Tor via SOCKS.
* **Server** (`server/`): FastAPI + SQLite; anonymous `/put`, short-lived `/session_token` for `/get`.

The design assumes **out-of-band key exchange** and focuses on **key continuity**, **anti-replay**, and practical client-side privacy (EXIF stripping, image bomb hardening, optional local encryption & secure mode).

---

## Table of Contents

   * [Overview](#overview)
   * [Table of Contents](#table-of-contents)
   * [Repository layout](#repository-layout)
   * [Protocol (client ↔ server)](#protocol-client-server)
      + [Cryptographic primitives](#cryptographic-primitives)
      + [Message payload (inside ciphertext)](#message-payload-inside-ciphertext)
      + [Server API](#server-api)
      + [Headers for signed endpoints](#headers-for-signed-endpoints)
      + [Proof-of-Work](#proof-of-work)
   * [Client details](#client-details)
      + [Key pinning & continuity](#key-pinning-continuity)
      + [Anti-replay](#anti-replay)
      + [Image safety](#image-safety)
      + [Clipboard auto-wipe (conditional)](#clipboard-auto-wipe-conditional)
      + [Local persistence](#local-persistence)
      + [Networking](#networking)
   * [Server internals](#server-internals)
      + [Schema](#schema)
      + [Cleanup](#cleanup)
   * [Threat model & known limitations](#threat-model-known-limitations)
   * [Building & packaging](#building-packaging)
      + [Client](#client)
      + [Server](#server)
   * [Configuration knobs](#configuration-knobs)
   * [Contributing](#contributing)
   * [License](#license)

---

## Repository layout

```
server/
  app.py            # FastAPI endpoints & periodic cleanup
  config_db.py      # config, DB connection, schema
  security.py       # header verification, PoW, tags, tokens
  schemas.py        # Pydantic models

client/
  app.py            # app logic, crypto flows, polling, UI glue
  interface.py      # dialogs, i18n, contact/identity managers, EXIF dialog
  security.py       # client crypto helpers (sign, encrypt, PoW), HTTP wrapper
  langs/            # fr.json, en.json

docs/
  img/              # screenshots (optional)
```

---

## Protocol (client ↔ server)

### Cryptographic primitives

* **Signing:** Ed25519 (PyNaCl `SigningKey` / `VerifyKey`)
* **Encryption:** NaCl **SealedBox** (X25519; Anonymous sender to recipient’s box key)
* **Hash:** SHA-256 (hex)

### Message payload (inside ciphertext)

For **text**:

```json
{
  "t": "text",
  "sender_box_pub": "<hex X25519>",
  "sender_sign_pub": "<hex Ed25519 verify key>",
  "text": "<string>",
  "ts": 1711111111,
  "sig": "<hex Ed25519(Sign(canonical(payload_without_sig)))>"
}
```

For **image/file**:

```json
{
  "t": "image" | "file",
  "sender_box_pub": "<hex>",
  "sender_sign_pub": "<hex>",
  "filename": "<string>",
  "mime": "<string|null>",
  "data_b64": "<base64>",
  "ts": 1711111111,
  "sig": "<hex>"
}
```

* **Canonicalization:** JSON dump with `separators=(',',':')`, `sort_keys=True`; the `sig` field is excluded from the signed bytes.
* **Anti-replay:** client stores `sha256(canonical_payload_without_sig)` in a per-conversation LRU (size \~500) and rejects duplicates; timestamps are accepted only within a ±48h window.

### Server API

* `GET /pow_salt` → `{ salt, difficulty, window_secs }`
* `POST /register` (signed headers) `{ box_pub }`

  * Upserts `(sign_pub → box_pub)`.
* `POST /session_token` (signed headers) → `{ token, expires_at }`

  * Binds a short-lived token to the user’s **recipient\_tag** (see below).
* `POST /put/` (anonymous + PoW)

  * Body: `{ recipient, expiration_time, cipher_hex, pow: { salt, nonce } }`
  * Server computes `recipient_tag = sha256_hex(recipient)`; stores `(tag, cipher, exp)`.
* `POST /get/` (token in header)

  * Deletes and returns all not-expired messages for the token’s `recipient_tag`.

### Headers for signed endpoints

```
X-PubSign: <hex Ed25519 verify key>
X-Timestamp: <unix seconds>
X-Signature: <hex Ed25519(Sign( f"{ts}.{sha256(body)}" ))>
```

* Allowed clock skew: ±300s (`ALLOWED_SKEW`).

### Proof-of-Work

* Server advertises a sliding **salt** window (`/pow_salt`).
* Client mines a **leading-zero** SHA-256 prefix over `salt || nonce || sha256(ciphertext)`.
* Difficulty and window are configured in `server/config.json`.

---

## Client details

### Key pinning & continuity

* Contacts record **both** keys:

  * `pub_hex` (X25519 encryption key)
  * `sign_pub_hex` (Ed25519 verify key)
* On message receive:

  * Verify Ed25519 signature over the canonical payload.
  * If the sender’s `sender_sign_pub` ≠ pinned `sign_pub_hex`, show a **key change** dialog.
  * No delivery occurs until the user accepts (and we update `sign_pub_hex`).

### Anti-replay

* For each conversation (keyed by `(my_identity_id, sender_box_pub)`), maintain an in-memory LRU of recent canonical payload hashes (`deque(maxlen=500)`), **persisted** in the vault.
* Drop messages with timestamps outside ±48h.

### Image safety

* **Decompression bomb hardening:**

  * `Image.MAX_IMAGE_PIXELS = 50_000_000`
  * `ImageFile.LOAD_TRUNCATED_IMAGES = False`
  * `Image.verify()` + re-open before rendering; downscale thumbnails in UI.
* **EXIF dialog** shown on image send:

  * Preview extracted EXIF/metadata (and some `info` chunks).
  * Optional **strip** (re-encode JPEG/PNG without EXIF/ancillary chunks).

### Clipboard auto-wipe (conditional)

* Copy actions for **encryption** and **signing** public keys schedule a wipe in **30s**.
* Wipe only if the clipboard **still** contains the same value (avoid clobbering).

### Local persistence

* **When not in Secure Mode:**

  * Conversations vault: `client/conversations.vault`
  * Encrypted with a **master key** derived via scrypt from the user’s password; files are atomically replaced on save.
  * Vault contains messages (binary parts as base64), unread counts, selection state, and the per-conversation anti-replay LRU.
* **Secure Mode:** no persistence; vault files are purged on enable/start/exit.

### Networking

* Optional Tor routing via SOCKS (`use_tor`, `socks_proxy`).
* Anonymous `/put/`; tokenized `/get/` with short-lived session tokens.
* Neutral request headers; no sender identity in payload to the server.

---

## Server internals

### Schema

```sql
CREATE TABLE users (
  sign_pub   TEXT PRIMARY KEY,
  box_pub    TEXT NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE messages (
  id             INTEGER PRIMARY KEY AUTOINCREMENT,
  recipient_tag  TEXT NOT NULL,
  cipher_hex     TEXT NOT NULL,
  expiration_time INTEGER NOT NULL
);

CREATE TABLE session_tokens (
  token         TEXT PRIMARY KEY,
  recipient_tag TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL
);
```

* `recipient_tag = sha256(box_pub_hex)` avoids storing raw pubkeys on the server.
* `/get/` deletes delivered messages using `DELETE ... RETURNING`.

### Cleanup

* Lifespan task periodically removes expired messages and tokens (`auto_clean_timer`).

---

## Threat model & known limitations

* **First contact (TOFU)**: If you add a contact from an unsolicited message, you trust the first key you saw. Prefer adding contacts **from out-of-band fingerprints**.
* **Key compromise**: If a contact’s signing private key is stolen, the attacker can sign valid messages. Key changes should always be verified out-of-band.
* **Metadata leakage**: The server learns the **recipient** (as a tag), timing, and message sizes. Use Tor and self-host to reduce linkage and retention risk.
* **Traffic analysis**: Out of scope; Tor/VPN recommended.

---

## Building & packaging

> Run these from the target folder.

### Client

* Common:

```bash
pip install -r requirements.txt
python app.py
```

* PyInstaller (Windows, one-file):

```powershell
cd client
pyinstaller --clean --noconfirm ^
  --onefile --noconsole ^
  --name EncryptedClient ^
  --add-data "langs;langs" ^
  app.py
```

* PyInstaller (macOS/Linux, one-file):

```bash
cd client
pyinstaller --clean --noconfirm \
  --onefile --noconsole \
  --name EncryptedClient \
  --add-data "langs:langs" \
  app.py
```

If hidden imports are needed:

```
--hidden-import "nacl.signing" --hidden-import "nacl.public" --hidden-import "nacl.bindings" --hidden-import "PIL._imaging"
```

### Server

```bash
cd server
python app.py
# or package:
pyinstaller --clean --noconfirm --onefile --name EncryptedServer app.py
```

---

## Configuration knobs

* **Server (`server/config.json`)**

  * `pow_difficulty` — raises PoW cost for `/put/`.
  * `pow_window_secs` — PoW salt window.
  * `session_token_ttl` — `/get/` token lifetime (seconds).
  * `auto_clean_timer` — cleanup loop period (seconds).

* **Client (`client/config.json`)**

  * `use_tor`, `socks_proxy` — network privacy.
  * `ask_set_password` — prompt to set a password at startup if none exists.
  * `secure_mode` — disable local persistence entirely.
  * `polling_base`, `polling_jitter` — fetch cadence (avoid fingerprintable odd values).

---

## Contributing

* Keep the **user security bar high by default**. New features should not weaken:

  * Key pinning & continuity
  * Anti-replay guarantees
  * Local encryption & safe defaults
* Prefer small, reviewable PRs with tests or clear manual test steps.
* Discuss protocol-level changes in issues first.

---

## License

**AGPL-3.0-or-later** — contributions are accepted under the same license.
