import json, time, hashlib, threading, random
from typing import Optional, Dict
from nacl.public import PublicKey, PrivateKey, SealedBox
from nacl.encoding import HexEncoder
from nacl.signing import SigningKey
import requests

# -------- JSON & hashing --------
def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def canonical_dumps(obj) -> bytes:
    # Deterministic JSON for signatures
    return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode()

# -------- HTTP client (headers/proxy/TOR) --------
_UA_POOL = [
    # Keep a small, realistic set (rotated once per session)
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/126.0",
]

_AL_POOL = [
    "en-US,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "en-GB,en;q=0.9",
]

class HttpClient:
    """
    Thin wrapper around requests.Session with:
      - optional TOR via SOCKS proxy
      - neutral, randomized headers per session
    """
    def __init__(self, use_tor: bool, socks_proxy_url: str):
        self.use_tor = bool(use_tor)
        self.socks_proxy_url = socks_proxy_url or "socks5h://127.0.0.1:9050"
        self._build_session()

    def _build_session(self):
        s = requests.Session()
        # Random-but-stable headers for this process
        s.headers.update({
            "User-Agent": random.choice(_UA_POOL),
            "Accept": "*/*",
            "Accept-Language": random.choice(_AL_POOL),
            "Cache-Control": "no-store",
            "Pragma": "no-cache",
            "Connection": "close",
        })
        if self.use_tor:
            # Requires requests[socks]
            s.proxies = {
                "http":  self.socks_proxy_url,
                "https": self.socks_proxy_url,
            }
        self._s = s

    def update(self, *, use_tor: Optional[bool]=None, socks_proxy_url: Optional[str]=None):
        if use_tor is not None:
            self.use_tor = bool(use_tor)
        if socks_proxy_url is not None:
            self.socks_proxy_url = socks_proxy_url
        self._build_session()

    # Thin passthroughs (override timeout per call if needed)
    def get(self, url, **kw):  return self._s.get(url, **kw)
    def post(self, url, **kw): return self._s.post(url, **kw)

# -------- Crypto payload --------
def encrypt_for(recipient_box_pub_hex: str, inner_payload: dict) -> str:
    blob = canonical_dumps(inner_payload)
    recip = PublicKey(recipient_box_pub_hex, encoder=HexEncoder)
    ct = SealedBox(recip).encrypt(blob)
    return ct.hex()

def decrypt_with(box_sk: PrivateKey, cipher_hex: str) -> bytes:
    ct = bytes.fromhex(cipher_hex)
    return SealedBox(box_sk).decrypt(ct)

# -------- Signed POST (register, session tokens, etc.) --------
def signed_post(http: HttpClient, url: str, payload: dict, sign_sk: SigningKey, sign_pk_hex: str):
    body = canonical_dumps(payload)
    ts = str(int(time.time()))
    to_sign = (ts + "." + sha256_hex(body)).encode()
    sig_hex = sign_sk.sign(to_sign).signature.hex()
    headers = {
        "Content-Type": "application/json",
        "X-PubSign":  sign_pk_hex,
        "X-Timestamp": ts,
        "X-Signature": sig_hex,
    }
    return http.post(url, data=body, headers=headers, timeout=15)

# -------- PoW (anonymous PUT) --------
class PoWHelper:
    """
    Fetches PoW salt/params from server and mines a small SHA-256 prefix.
    Thread-safe mining (single miner at a time per instance).
    """
    def __init__(self, server_url: str, http: HttpClient):
        self.server_url = server_url
        self.http = http
        self.salt = None
        self.difficulty = 5
        self.window_secs = 120
        self.last_fetch = 0
        self._lock = threading.Lock()

    def _refresh_if_needed(self):
        now = time.time()
        if self.salt and now - self.last_fetch < self.window_secs / 2:
            return
        try:
            r = self.http.get(self.server_url.rstrip("/") + "/pow_salt", timeout=10)
            j = r.json()
            self.salt = j.get("salt")
            self.difficulty = int(j.get("difficulty", 5))
            self.window_secs = int(j.get("window_secs", 120))
            self.last_fetch = now
        except Exception:
            # Fallback windowed salt (still throttles)
            self.salt = str(int(now // max(self.window_secs or 120, 1)))
            self.difficulty = 5

    def compute_nonce(self, cipher_hex: str, progress_hook=None, cancel_event=None) -> str:
        with self._lock:
            self._refresh_if_needed()
            salt = self.salt or str(int(time.time() // max(self.window_secs or 120, 1)))
            target_prefix = "0" * int(self.difficulty)
            ct = bytes.fromhex(cipher_hex)
            # Hash ciphertext once to speed the inner loop
            ct_digest = hashlib.sha256(ct).digest()

            nonce_int = 0
            # Expected average trials for n hex zeros ≈ 16^n
            expected = max(1, 16 ** int(self.difficulty))
            step = 5000

            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise RuntimeError("CANCELLED")
                nonce = nonce_int.to_bytes(8, "big")
                h = sha256_hex(salt.encode() + nonce + ct_digest)
                if h.startswith(target_prefix):
                    if progress_hook:
                        try: progress_hook(expected, expected)
                        except: pass
                    return nonce.hex()
                nonce_int += 1
                if progress_hook and (nonce_int % step == 0):
                    try: progress_hook(nonce_int, expected)
                    except: pass
