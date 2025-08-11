import os, json, sqlite3

CONFIG_FILE = "config.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        cfg = {
            "database": "messages.db",
            "port": 8000,
            "host": "0.0.0.0",
            "pow_difficulty": 5,   # ~20 bits
            "pow_window_secs": 120
        }
        with open(CONFIG_FILE, "w") as f: json.dump(cfg, f, indent=4)
        return cfg
    with open(CONFIG_FILE, "r") as f: 
        return json.load(f)

config = load_config()

DATABASE = config["database"]
PORT     = config["port"]
HOST     = config["host"]
POW_DIFF = int(config.get("pow_difficulty", 5))
POW_WIN  = int(config.get("pow_window_secs", 120))

def connect():
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    conn.execute("PRAGMA secure_delete=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def ensure_schema():
    conn = connect(); cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            sign_pub   TEXT PRIMARY KEY,
            box_pub    TEXT NOT NULL,
            created_at INTEGER NOT NULL
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS messages (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            recipient      TEXT NOT NULL,
            cipher_hex     TEXT NOT NULL,
            created_at     INTEGER NOT NULL,
            expiration_time INTEGER NOT NULL,
            delivered_at   INTEGER
        )
    """)
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages(recipient)")
    cur.execute("CREATE INDEX IF NOT EXISTS idx_messages_exp ON messages(expiration_time)")
    conn.commit(); conn.close()
