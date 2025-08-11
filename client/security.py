import json, time, hashlib, requests, threading
from nacl.public import PublicKey, PrivateKey, SealedBox
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey

# ---------- JSON & hash ----------
def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def canonical_dumps(obj) -> bytes:
    # JSON canonique pour signature (stable & minimal)
    return json.dumps(obj, separators=(',',':'), sort_keys=True).encode()

# ---------- Crypto payload ----------
def encrypt_for(recipient_box_pub_hex: str, inner_payload: dict) -> str:
    blob = canonical_dumps(inner_payload)
    recip = PublicKey(recipient_box_pub_hex, encoder=HexEncoder)
    ct = SealedBox(recip).encrypt(blob)
    return ct.hex()

def decrypt_with(box_sk: PrivateKey, cipher_hex: str) -> bytes:
    ct = bytes.fromhex(cipher_hex)
    return SealedBox(box_sk).decrypt(ct)

# ---------- HTTP signé (GET/ACK/DELETE/REGISTER) ----------
def signed_post(url: str, payload: dict, sign_sk: SigningKey, sign_pk_hex: str) -> requests.Response:
    body = canonical_dumps(payload)
    ts = str(int(time.time()))
    to_sign = (ts + "." + sha256_hex(body)).encode()
    sig_hex = sign_sk.sign(to_sign).signature.hex()
    headers = {
        "Content-Type": "application/json",
        "X-PubSign": sign_pk_hex,
        "X-Timestamp": ts,
        "X-Signature": sig_hex
    }
    return requests.post(url, data=body, headers=headers, timeout=10)

# ---------- PoW (PUT anonyme) ----------
class PoWHelper:
    def __init__(self, server_url: str):
        self.server_url = server_url
        self.salt = None
        self.difficulty = 5
        self.window_secs = 120
        self.last_fetch = 0
        self._lock = threading.Lock()  # évite plusieurs minages concurrents

    def _refresh_if_needed(self):
        now = time.time()
        if self.salt and now - self.last_fetch < self.window_secs/2:
            return
        try:
            r = requests.get(self.server_url.rstrip("/") + "/pow_salt", timeout=10)
            j = r.json()
            self.salt = j.get("salt")
            self.difficulty = int(j.get("difficulty", 5))
            self.window_secs = int(j.get("window_secs", 120))
            self.last_fetch = now
        except Exception:
            # fallback si /pow_salt indisponible
            self.salt = str(int(now // max(self.window_secs, 1)))
            self.difficulty = 5

    def compute_nonce(self, cipher_hex: str, progress_hook=None, cancel_event=None) -> str:
        # Minage protégé par un lock pour ne pas partir en parallèle
        with self._lock:
            self._refresh_if_needed()
            salt = self.salt or str(int(time.time() // max(self.window_secs, 1)))
            target_prefix = "0" * int(self.difficulty)
            ct = bytes.fromhex(cipher_hex)
            ct_digest = hashlib.sha256(ct).digest()

            nonce_int = 0
            # Estimation moyenne d’essais pour un préfixe hex de n zéros = 16^n
            expected = max(1, 16 ** int(self.difficulty))
            step = 5000  # fréquence d’update

            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError("CANCELLED")

                nonce = nonce_int.to_bytes(8, "big")
                h = sha256_hex(salt.encode() + nonce + ct_digest)
                if h.startswith(target_prefix):
                    if progress_hook:
                        try: progress_hook(expected, expected)  # 100 %
                        except: pass
                    return nonce.hex()

                nonce_int += 1
                if progress_hook and (nonce_int % step == 0):
                    try: progress_hook(nonce_int, expected)
                    except: pass
