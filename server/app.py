from fastapi import FastAPI, HTTPException, Request
from typing import List, AsyncIterator
from contextlib import asynccontextmanager
import asyncio, logging, time

from config_db import ensure_schema, connect, HOST, PORT, POW_DIFF, POW_WIN, AUTO_CLEAN_TIMER
from security import (
    read_body, verify_signature_headers, require_known_user
)
from schemas import RegisterIn, PutIn, GetIn

# ---------- Lifespan (startup/shutdown) ----------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    ensure_schema()
    stop_event = asyncio.Event()

    async def cleaner():
        logger = logging.getLogger("cleanup")
        while not stop_event.is_set():
            try:
                now = int(time.time())
                conn = connect(); cur = conn.cursor()
                cur.execute("DELETE FROM messages WHERE expiration_time < ?", (now,))
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

app = FastAPI(title="Encrypted Messaging Server", version="4.0", lifespan=lifespan)

# ---------- Endpoints ----------
@app.get("/health")
def health():
    return {"status": "ok", "time": int(time.time())}

@app.get("/about")
def about():
    return {
        "name": "Encrypted Messaging App",
        "license": "AGPL-3.0-or-later",
        "source": "https://github.com/Deadman69/Encrypted-Communications"
    }

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
        return {"status": "registered", "sign_pub": sign_pub}
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

@app.post("/put/")
def put_message(msg: PutIn):
    from security import check_pow
    if not isinstance(msg.pow, dict) or "salt" not in msg.pow or "nonce" not in msg.pow:
        raise HTTPException(400, "Missing PoW")
    if not check_pow(msg.pow["salt"], msg.pow["nonce"], msg.cipher_hex):
        raise HTTPException(400, "Invalid PoW")
    try:
        now = int(time.time())
        conn = connect(); cur = conn.cursor()
        cur.execute("""
            INSERT INTO messages (recipient, cipher_hex, created_at, expiration_time, delivered_at)
            VALUES (?, ?, ?, ?, NULL)
        """, (msg.recipient, msg.cipher_hex, now, msg.expiration_time))
        conn.commit(); mid = cur.lastrowid; conn.close()
        return {"status": "stored", "id": mid}
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

@app.post("/get/")
async def get_messages(request: Request, q: GetIn):
    body = await read_body(request)
    sign_pub = request.headers.get("X-PubSign","")
    ts = request.headers.get("X-Timestamp","")
    sig = request.headers.get("X-Signature","")
    verify_signature_headers(sign_pub, ts, sig, body)
    box_pub_allowed = require_known_user(sign_pub)
    if q.recipient != box_pub_allowed:
        raise HTTPException(403, "Forbidden recipient")

    try:
        now = int(time.time())
        conn = connect(); cur = conn.cursor()

        # Get & delete in the same request
        cur.execute("""
            DELETE FROM messages
             WHERE recipient=? AND expiration_time>?
             RETURNING id, cipher_hex, expiration_time
        """, (q.recipient, now))
        rows = cur.fetchall()
        conn.commit(); conn.close()

        msgs = [{"id": r[0], "cipher_hex": r[1], "expiration_time": r[2]} for r in rows]
        return {"messages": msgs}
    except Exception as e:
        raise HTTPException(500, f"Server error: {e}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=HOST,
        port=PORT,
        access_log=False,
        log_level="warning"
    )
