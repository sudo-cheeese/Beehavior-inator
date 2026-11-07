
import sqlite3
import json
from pathlib import Path
from datetime import datetime, timezone

BASE_DIR = Path(__file__).resolve().parent
DB_FILE = BASE_DIR / "parsed" / "honeypot.db"


def get_connection():
    conn = sqlite3.connect(DB_FILE, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                src_ip TEXT,
                method TEXT,
                path TEXT,
                host TEXT,
                user_agent TEXT,
                referer TEXT,
                content_type TEXT,
                content_length INTEGER,
                post_body TEXT,
                cf_connecting_ip TEXT,
                cf_country TEXT,
                raw_json TEXT,
                ingested_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_insights (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generated_at TEXT NOT NULL,
                period_start TEXT,
                period_end TEXT,
                model TEXT,
                summary TEXT,
                raw_json TEXT
            )
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_timestamp
            ON events(ts)
        """)

        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_events_ip
            ON events(src_ip)
        """)


def save_events(events):
    if not events:
        return 0

    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.executemany("""
            INSERT INTO events (
                ts, src_ip, method, path, host,
                user_agent, referer, content_type,
                content_length, post_body,
                cf_connecting_ip, cf_country,
                raw_json, ingested_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, [
            (
                event.get("ts"),
                event.get("src_ip"),
                event.get("method"),
                event.get("path"),
                event.get("host"),
                event.get("user_agent"),
                event.get("referer"),
                event.get("content_type"),
                event.get("content_length"),
                event.get("post_body"),
                event.get("cf_connecting_ip"),
                event.get("cf_country"),
                json.dumps(event),
                now
            )
            for event in events
        ])

    return len(events)


def save_insight(summary, model, details=None):
    now = datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        conn.execute("""
            INSERT INTO ai_insights (
                generated_at, model, summary, raw_json
            )
            VALUES (?, ?, ?, ?)
        """, (
            now,
            model,
            summary,
            json.dumps(details or {})
        ))


if __name__ == "__main__":
    init_db()
    print(f"Database initialized: {DB_FILE}")

