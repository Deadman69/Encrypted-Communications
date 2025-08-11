import time, hashlib, secrets
from fastapi import HTTPException, Request
from nacl.signing import VerifyKey
from config_db import connect, POW_WIN, POW_DIFF

ALLOWED_SKEW = 300  # seconds

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
    return row[0]

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
        ct_digest = hashlib.sha256(ct).digest()
    except Exception:
        return False
    h = sha256_hex(salt.encode() + nonce + ct_digest)
    return h.startswith("0" * POW_DIFF)

def recipient_tag_of(box_pub_hex: str) -> str:
    # Hash the hex string itself; client never sends/stores the tag
    return hashlib.sha256(box_pub_hex.encode()).hexdigest()

def issue_session_token(recipient_tag: str, ttl: int) -> (str, int):
    now = int(time.time())
    token = secrets.token_urlsafe(32)
    exp = now + int(ttl)
    conn = connect(); cur = conn.cursor()
    cur.execute("INSERT INTO session_tokens(token, recipient_tag, created_at, expires_at) VALUES (?,?,?,?)",
                (token, recipient_tag, now, exp))
    conn.commit(); conn.close()
    return token, exp

def validate_session_token(token: str) -> str:
    if not token:
        raise HTTPException(401, "Missing token")
    now = int(time.time())
    conn = connect(); cur = conn.cursor()
    cur.execute("SELECT recipient_tag, expires_at FROM session_tokens WHERE token=?", (token,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(401, "Invalid token")
    recipient_tag, exp = row[0], int(row[1])
    if exp < now:
        try:
            cur.execute("DELETE FROM session_tokens WHERE token=?", (token,))
            conn.commit()
        finally:
            conn.close()
        raise HTTPException(401, "Expired token")
    conn.close()
    return recipient_tag
