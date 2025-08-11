# Encrypted Messaging App

A minimal, privacy-first desktop messenger with **end-to-end encryption**, sealed-sender style delivery (the server never learns who sent a message), and a simple **Tkinter** UI.

> This project is open-source. For maximum trust, you are encouraged to **self-host the server from source** so you control retention and metadata, and to avoid any attempt to deanonymize users.

---

## Table of Contents

  * [Encrypted Messaging App](#encrypted-messaging-app)
  * [Table of Contents](#table-of-contents)
  * [Highlights](#highlights)
  * [Quick Start](#quick-start)
    + [1) Run the server (recommended: self-host)](#1-run-the-server-recommended-self-host)
    + [2) Run the client](#2-run-the-client)
  * [Using the app](#using-the-app)
  * [Privacy & Safety recommendations](#privacy-safety-recommendations)
  * [What this app does *not* do](#what-this-app-does-not-do)
  * [Troubleshooting](#troubleshooting)
  * [License](#license)
  * [Credits](#credits)

---

## Highlights

* **End-to-end encryption**

  * Messages (text/files/images + metadata needed for the recipient) are **signed** (Ed25519) and **encrypted** (NaCl SealedBox/X25519).
* **Sealed-sender style upload**

  * The server only sees: recipient public key, ciphertext, expiration time, and a PoW nonce.
* **Multiple identities**

  * Maintain several identities; each contact is bound to one of your identities.
* **Key authenticity & continuity**

  * Contacts **pin** the sender’s signing key. Key changes trigger an explicit warning.
* **Anti-replay**

  * Duplicate (replayed) payloads are rejected; very old/far-future timestamps are ignored.
* **Image privacy**

  * Preview **EXIF metadata** before sending and optionally **strip EXIF** with one click.
  * Protection against **image decompression bombs** (hard pixel cap + strict decoding).
* **Secure local usage**

  * Optional **password** to encrypt all local data (identities, contacts, conversations).
  * **Secure Mode** to leave no trace (no local persistence while enabled).
* **Clipboard safety**

  * Copying your public keys can auto-clear the clipboard **after 30 seconds** (only if unchanged).

---

## Quick Start

### 1) Run the server (recommended: self-host)

```bash
# In a new terminal
cd server
python app.py
# Default: http://localhost:8000
```

A `server/config.json` is created on first run:

```json
{
  "database": "messages.db",
  "port": 8000,
  "host": "0.0.0.0",
  "pow_difficulty": 5,
  "pow_window_secs": 120,
  "auto_clean_timer": 60,
  "session_token_ttl": 300
}
```

### 2) Run the client

```bash
cd client
python app.py
```

A `client/config.json` is created on first run:

```json
{
  "server_url": "http://localhost:8000",
  "language": "en",
  "secure_mode": false,
  "ask_set_password": true,
  "use_tor": false,
  "socks_proxy": "socks5h://127.0.0.1:9050",
  "polling_base": 5.0,
  "polling_jitter": 3.0
}
```

> **Tip:** If you enable Tor, keep `use_tor: true` and ensure your SOCKS proxy is reachable.

---

## Using the app

1. **Create an identity**

   * Open **Identities** → **Add**. You can keep the generated keys.
   * Buttons allow you to copy:

     * **Encryption public key** (X25519)
     * **Signing public key** (Ed25519)
       Clipboard auto-clears after 30s if unchanged.

2. **Add a contact**

   * Open **Contacts** → **Add**.
   * Paste your contact’s **encryption** and **signing** public keys (hex), and select which of your identities you’ll use to message them.
   * Keys should be exchanged **out-of-band** (in person, voice, etc.) and fingerprints verified.

3. **Start a conversation**

   * Click **New**, pick a contact, type and **Send**.
   * Attach images/files with the paperclip.
   * For images, an **EXIF** dialog lets you view and optionally **remove** metadata before sending.

4. **Receiving from unknown senders**

   * If someone messages you before you saved them, the header shows **Add contact**.
     Only add them if you can verify their fingerprints **out-of-band**.

5. **Key change warnings**

   * If a saved contact’s **signing key** changes, you’ll see an alert with old/new fingerprints.
     **Do not accept** unless you verify the change **out-of-band**.

6. **Secure Mode**

   * Toggle **Secure mode** in the left pane:

     * When enabled, **no identities/contacts/messages are kept on disk**.
     * On exit, you’ll be reminded that everything will be purged.

---

## Privacy & Safety recommendations

* **Self-host the server** (from this repository) to control retention and metadata exposure.
* **Verify fingerprints out-of-band** when adding contacts and on any key change.
* Prefer **Tor** (or a trusted VPN) for the client’s network path.
* Before sending photos, **strip EXIF** (especially GPS) unless you intend to share it.
* Treat **filenames** like content: the recipient will see them; rename if sensitive.
* Use a **strong password** for local encryption; write it down securely. If you lose it, local data cannot be recovered.
* Keep the app up to date.

---

## What this app does *not* do

* It does not magically prove **who** someone is; it proves **key ownership**. You must verify keys out-of-band.
* It does not protect from a compromised contact device (if their private keys are stolen, the attacker can sign messages).
* It cannot prevent traffic analysis at the network layer; use Tor/VPN to reduce this.

---

## Troubleshooting

* **“Server: offline”** → Ensure the server is running and `server_url` is correct.
* **PoW feels slow** → Lower `pow_difficulty` on the server; it’s a global setting.
* **Image won’t display** → It may exceed the pixel cap or be malformed; you’ll still get a safe “\[image]” placeholder.
* **Local vault issues** → If you set a password later, existing files are migrated and encrypted automatically. If migration fails, you can delete the vault (you’ll lose local history).

---

## License

**AGPL-3.0-or-later** — see `LICENSE`.

---

## Credits

* Crypto: **PyNaCl** (Ed25519, X25519/SealedBox)
* Backend: **FastAPI** + Uvicorn + SQLite
* UI: **Tkinter** + **Pillow**