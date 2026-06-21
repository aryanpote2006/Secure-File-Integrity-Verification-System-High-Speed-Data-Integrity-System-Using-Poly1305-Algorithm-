import sqlite3
from pathlib import Path

from flask import current_app, g


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    reset_token TEXT,
    reset_token_expiry TEXT,
    reset_requested_at TEXT,
    password_updated_at TEXT,
    session_version INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_path TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    mime_type TEXT,
    file_hash TEXT NOT NULL,
    key_salt TEXT NOT NULL,
    poly1305_mac TEXT NOT NULL,
    upload_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    uploaded_by INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'stored',
    FOREIGN KEY (uploaded_by) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS verification_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER,
    user_id INTEGER,
    verification_date TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    result TEXT NOT NULL,
    remarks TEXT NOT NULL,
    ip_address TEXT,
    submitted_filename TEXT,
    calculated_mac TEXT,
    stored_mac TEXT,
    FOREIGN KEY (file_id) REFERENCES files (id),
    FOREIGN KEY (user_id) REFERENCES users (id)
);

CREATE TABLE IF NOT EXISTS password_reset_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email_hash TEXT NOT NULL,
    ip_address TEXT,
    requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""

MIGRATIONS = {
    "users": {
        "reset_token": "ALTER TABLE users ADD COLUMN reset_token TEXT",
        "reset_token_expiry": "ALTER TABLE users ADD COLUMN reset_token_expiry TEXT",
        "reset_requested_at": "ALTER TABLE users ADD COLUMN reset_requested_at TEXT",
        "password_updated_at": "ALTER TABLE users ADD COLUMN password_updated_at TEXT",
        "session_version": "ALTER TABLE users ADD COLUMN session_version INTEGER NOT NULL DEFAULT 0",
    }
}


def get_db():
    if "db" not in g:
        db_path = Path(current_app.config["DATABASE"])
        db_path.parent.mkdir(parents=True, exist_ok=True)
        g.db = sqlite3.connect(db_path)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(SCHEMA)
    run_migrations(db)
    db.commit()


def run_migrations(db):
    for table, columns in MIGRATIONS.items():
        existing = {row["name"] for row in db.execute(f"PRAGMA table_info({table})").fetchall()}
        for column, statement in columns.items():
            if column not in existing:
                db.execute(statement)


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
