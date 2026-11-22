"""SQLite storage. Every call opens its own connection, so threads never share one."""
import sqlite3
import threading
import time
from contextlib import contextmanager

SCHEMA = """
CREATE TABLE IF NOT EXISTS links (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                 -- file | note
    owner_token TEXT NOT NULL,
    auth_hash TEXT NOT NULL,            -- SHA-256 of a token only the link holder can derive
    enc_meta TEXT NOT NULL,             -- encrypted {name, type}
    size INTEGER NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    max_downloads INTEGER NOT NULL,
    downloads INTEGER NOT NULL DEFAULT 0,
    failures INTEGER NOT NULL DEFAULT 0,
    password INTEGER NOT NULL DEFAULT 0,
    salt TEXT,
    status TEXT NOT NULL DEFAULT 'active',  -- active | downloaded | expired | revoked | locked
    ended_at REAL
);
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    owner_token TEXT NOT NULL,
    title TEXT NOT NULL,
    public_key TEXT NOT NULL,
    created REAL NOT NULL,
    expires REAL NOT NULL,
    max_uploads INTEGER NOT NULL,
    received INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'open',    -- open | closed
    ended_at REAL
);
CREATE TABLE IF NOT EXISTS uploads (
    id TEXT PRIMARY KEY,
    request_id TEXT NOT NULL,
    enc_meta TEXT NOT NULL,
    wrapped_key TEXT NOT NULL,
    size INTEGER NOT NULL,
    created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS friends (
    fp TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    pub TEXT NOT NULL,
    added REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS inbox (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER NOT NULL,
    sha TEXT NOT NULL,
    from_name TEXT NOT NULL,
    from_fp TEXT NOT NULL,
    friend INTEGER NOT NULL,
    plain INTEGER NOT NULL,
    received REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    n INTEGER PRIMARY KEY AUTOINCREMENT,
    at REAL NOT NULL,
    kind TEXT NOT NULL,
    ref TEXT,
    text TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS settings (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chats (
    mid TEXT PRIMARY KEY,
    peer_fp TEXT NOT NULL,
    peer_name TEXT NOT NULL,
    direction TEXT NOT NULL,            -- in | out
    text TEXT NOT NULL,
    at REAL NOT NULL,
    ttl INTEGER NOT NULL,
    expires REAL,                       -- NULL = keep
    status TEXT NOT NULL,               -- sending | delivered | failed | received
    error TEXT,
    read INTEGER NOT NULL DEFAULT 0
);
"""


class DB:
    def __init__(self, path: str):
        self.path = path
        self.lock = threading.RLock()  # serialises read-modify-write sequences
        with self.conn() as c:
            c.executescript(SCHEMA)
            c.execute("PRAGMA journal_mode=WAL")

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path, timeout=15)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    def event(self, kind: str, ref: str, text: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO events (at, kind, ref, text) VALUES (?,?,?,?)",
                      (time.time(), kind, ref, text))

    def setting(self, key: str, default: str) -> str:
        with self.conn() as c:
            row = c.execute("SELECT v FROM settings WHERE k=?", (key,)).fetchone()
        return row["v"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        with self.conn() as c:
            c.execute("INSERT INTO settings (k, v) VALUES (?, ?) "
                      "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (key, value))
