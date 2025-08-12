from fastapi import FastAPI, HTTPException, Request
from typing import AsyncIterator
from contextlib import asynccontextmanager
import asyncio, logging, time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse

from config_db import ensure_schema, connect, HOST, PORT, POW_DIFF, POW_WIN, AUTO_CLEAN_TIMER, SESSION_TOKEN_TTL, MAX_MESSAGE_TTL, MAX_BODY_BYTES
from security import (
    read_body, verify_signature_headers, require_known_user,
    check_pow, recipient_tag_of, issue_session_token, validate_session_token
)
from schemas import RegisterIn, PutIn

# ----- lifespan: periodic cleanup -----
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    ensure_schema()
    stop_event = asyncio.Event()
    logger = logging.getLogger("cleanup")

    async def cleaner():
        while not stop_event.is_set():
            try:
                now = int(time.time())
                conn = connect(); cur = conn.cursor()
                # delete expired messages
                cur.execute("DELETE FROM messages WHERE expiration_time < ?", (now,))
                # delete expired tokens
                cur.execute("DELETE FROM session_tokens WHERE expires_at < ?", (now,))
                conn.commit(); conn.close()
            except Exception as e:
                logger.warning("cleanup error: %s", e)
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=AUTO_CLEAN_TIMER)
            except asyncio.TimeoutError:
                pass

    task = asyncio.create_task(cleaner())
    try:
        yield
    finally:
        stop_event.set()
        task.cancel()
        try:
            await task
        except Exception:
            pass

class BodySizeLimitMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            cl = request.headers.get("content-length")
            if cl and int(cl) > MAX_BODY_BYTES:
                return PlainTextResponse("Payload too large", status_code=413)
        except Exception:
            pass
        # On lit le body une seule fois : FastAPI le mettra en cache pour Pydantic.
        body = await request.body()
        if len(body) > MAX_BODY_BYTES:
            return PlainTextResponse("Payload too large", status_code=413)
        async def receive_gen():
            return {"type": "http.request", "body": body, "more_body": False}
        request._receive = receive_gen
        return await call_next(request)

app = FastAPI(title="Encrypted Messaging Server", version="5.0", lifespan=lifespan)
app.add_middleware(BodySizeLimitMiddleware)

# ----- endpoints -----
@app.get("/health")
def health():
    return {"status": "ok", "time": int(time.time())}

@app.get("/about")
def about():
    return {"name": "Encrypted Messaging App", "license": "AGPL-3.0-or-later"}

@app.get("/pow_salt")
def pow_salt():
    now = int(time.time())
    return {"salt": str(now // POW_WIN), "difficulty": POW_DIFF, "window_secs": POW_WIN}

@app.post("/register")
async def register(request: Request, payload: RegisterIn):
    body = await read_body(request)
    sign_pub = request.headers.get("X-PubSign","")
    ts = request.headers.get("X-Timestamp","")
    sig = request.headers.get("X-Signature","")
    verify_signature_headers(sign_pub, ts, sig, body)
    try:
        now = int(time.time())
        conn = connect(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO users(sign_pub, box_pub, created_at)
            VALUES(?,?,?)
            ON CONFLICT(sign_pub) DO UPDATE SET box_pub=excluded.box_pub
        """, (sign_pub, payload.box_pub, now))
        conn.commit(); conn.close()
        return {"status": "registered"}
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

@app.post("/session_token")
async def session_token(request: Request):
    # Signed headers prove the identity; the token is short-lived and used for /get/
    body = await read_body(request)
    sign_pub = request.headers.get("X-PubSign","")
    ts = request.headers.get("X-Timestamp","")
    sig = request.headers.get("X-Signature","")
    verify_signature_headers(sign_pub, ts, sig, body)
    try:
        box_pub = require_known_user(sign_pub)
        tag = recipient_tag_of(box_pub)
        token, exp = issue_session_token(tag, SESSION_TOKEN_TTL)
        return {"token": token, "expires_at": exp}
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

@app.post("/put/")
def put_message(msg: PutIn):
    if not isinstance(msg.pow, dict) or "salt" not in msg.pow or "nonce" not in msg.pow:
        raise HTTPException(400, "Missing PoW")
    if not check_pow(msg.pow["salt"], msg.pow["nonce"], msg.cipher_hex):
        raise HTTPException(400, "Invalid PoW")

    from config_db import DATABASE, MAX_DB_BYTES, WARN_DB_BYTES
    try:
        size = os.path.getsize(DATABASE) if os.path.exists(DATABASE) else 0
        if size >= MAX_DB_BYTES:
            raise HTTPException(507, "Database is full")
        elif size >= WARN_DB_BYTES:
            logging.getLogger("db").warning("DB size warning: %d bytes >= warn threshold %d", size, WARN_DB_BYTES)
    except Exception:
        pass

    try:
        conn = connect(); cur = conn.cursor()
        tag = recipient_tag_of(msg.recipient)
        cur.execute("""
            INSERT INTO messages (recipient_tag, cipher_hex, expiration_time)
            VALUES (?, ?, ?)
        """, (tag, msg.cipher_hex, min(int(msg.expiration_time), time.time() + MAX_MESSAGE_TTL)))
        conn.commit(); mid = cur.lastrowid; conn.close()
        return {"status": "stored"}
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

@app.post("/get/")
async def get_messages(request: Request):
    # Token-only endpoint. Body is ignored; token in header drives selection.
    token = request.headers.get("X-Session-Token", "")
    try:
        tag = validate_session_token(token)
        now = int(time.time())
        conn = connect(); cur = conn.cursor()
        cur.execute("""
            DELETE FROM messages
             WHERE recipient_tag=? AND expiration_time>?
             RETURNING id, cipher_hex, expiration_time
        """, (tag, now))
        rows = cur.fetchall()
        conn.commit(); conn.close()
        msgs = [{"id": r[0], "cipher_hex": r[1], "expiration_time": r[2]} for r in rows]
        return {"messages": msgs}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=HOST, port=PORT, access_log=False, log_level="warning")
