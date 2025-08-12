import os, json, sqlite3, hashlib, time

if tuple(map(int, sqlite3.sqlite_version.split("."))) < (3, 35, 0):
    raise RuntimeError("SQLite >= 3.35.0 is required for DELETE ... RETURNING")

CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        cfg = {
            "database": "messages.db",
            "port": 8000,
            "host": "0.0.0.0",
            "pow_difficulty": 5,
            "pow_window_secs": 120,
            "auto_clean_timer": 60,
            "session_token_ttl": 300,

            "max_message_ttl_secs": 604800,
            "max_body_bytes": 314572800, # 300 MiB max per request
            "max_db_bytes": 524288000, # 500 MiB database max size 
            "warn_db_bytes": 314572800 # 300 MiB database warning size
        }
        with open(CONFIG_FILE, "w") as f: json.dump(cfg, f, indent=4)
        return cfg
    with open(CONFIG_FILE, "r") as f:
        return json.load(f)

config   = load_config()
DATABASE = config["database"]
PORT     = config["port"]
HOST     = config["host"]
POW_DIFF = int(config.get("pow_difficulty", 5))
POW_WIN  = int(config.get("pow_window_secs", 120))
AUTO_CLEAN_TIMER   = int(config.get("auto_clean_timer", 120))
SESSION_TOKEN_TTL  = int(config.get("session_token_ttl", 300))
MAX_MESSAGE_TTL  = int(config.get("max_message_ttl_secs", 7*24*3600))
MAX_BODY_BYTES   = int(config.get("max_body_bytes", 300*1024*1024))
MAX_DB_BYTES     = int(config.get("max_db_bytes", 500*1024*1024))
WARN_DB_BYTES    = int(config.get("warn_db_bytes", 300*1024*1024))

def connect():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def _sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()

def ensure_schema():
    conn = connect(); cur = conn.cursor()

    # users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            sign_pub   TEXT PRIMARY KEY,
            box_pub    TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)

    # messages (new schema: recipient_tag only)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient_tag  TEXT NOT NULL,
            cipher_hex     TEXT NOT NULL,
            expiration_time INTEGER NOT NULL
        )
    """)
    # migrate from old schema if needed
    cur.execute("PRAGMA table_info(messages)")
    cols = [r[1] for r in cur.fetchall()]
    if "recipient" in cols or "created_at" in cols or "delivered_at" in cols:
        # A very old schema; rebuild fresh table and copy
        cur.execute("CREATE TABLE IF NOT EXISTS messages_new (id INTEGER PRIMARY KEY AUTOINCREMENT, recipient_tag TEXT NOT NULL, cipher_hex TEXT NOT NULL, expiration_time INTEGER NOT NULL)")
        try:
            for (mid, recip, ct, exp) in cur.execute("SELECT id, recipient, cipher_hex, expiration_time FROM messages"):
                cur.execute("INSERT INTO messages_new (id, recipient_tag, cipher_hex, expiration_time) VALUES (?,?,?,?)",
                            (mid, _sha256_hex(recip), ct, exp))
        except Exception:
            pass
        cur.execute("DROP TABLE messages")
        cur.execute("ALTER TABLE messages_new RENAME TO messages")

    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient_tag ON messages(recipient_tag)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_exp ON messages(expiration_time)")

    # session tokens
    cur.execute("""
        CREATE TABLE IF NOT EXISTS session_tokens (
            token       TEXT PRIMARY KEY,
            recipient_tag TEXT NOT NULL,
            created_at  INTEGER NOT NULL,
            expires_at  INTEGER NOT NULL
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_exp ON session_tokens(expires_at)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_tokens_rec ON session_tokens(recipient_tag)")

    conn.commit(); conn.close()
