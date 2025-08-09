import time, hashlib
from fastapi import HTTPException, Request
from nacl.signing import VerifyKey

from config_db import connect, POW_WIN, POW_DIFF

ALLOWED_SKEW = 300  # 5 minutes

def sha256_hex(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

async def read_body(request: Request) -> bytes:
    return await request.body()

def verify_signature_headers(sign_pub_hex: str, ts_str: str, sig_hex: str, body: bytes) -> None:
    if not sign_pub_hex or not ts_str or not sig_hex:
        raise HTTPException(401, "Missing auth headers")
    try:
        ts = int(ts_str)
    except Exception:
        raise HTTPException(401, "Bad timestamp")
    now = int(time.time())
    if abs(now - ts) > ALLOWED_SKEW:
        raise HTTPException(401, "Stale timestamp")
    msg = (str(ts) + "." + sha256_hex(body)).encode()
    try:
        VerifyKey(bytes.fromhex(sign_pub_hex)).verify(msg, bytes.fromhex(sig_hex))
    except Exception:
        raise HTTPException(401, "Bad signature")

def require_known_user(sign_pub_hex: str) -> str:
    conn = connect(); cur = conn.cursor()
    cur.execute("SELECT box_pub FROM users WHERE sign_pub=?", (sign_pub_hex,))
    row = cur.fetchone(); conn.close()
    if not row:
        raise HTTPException(401, "Unknown user")
    return row[0]  # box_pub autorisé

def current_pow_salts():
    now = int(time.time())
    w = POW_WIN
    return {str(now // w), str((now - w) // w)}

def check_pow(salt: str, nonce_hex: str, cipher_hex: str) -> bool:
    if salt not in current_pow_salts():
        return False
    try:
        nonce = bytes.fromhex(nonce_hex)
        ct = bytes.fromhex(cipher_hex)
    except Exception:
        return False
    h = sha256_hex(salt.encode() + nonce + ct)
    return h.startswith("0" * POW_DIFF)
