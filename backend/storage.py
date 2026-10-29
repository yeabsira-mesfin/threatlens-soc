"""Small local SQLite persistence layer. Intended for isolated demos only."""
import os
import sqlite3
from pathlib import Path
from contextlib import contextmanager

def database_path():
    return Path(os.environ.get('THREATLENS_DB', str(Path(__file__).parent / 'data' / 'threatlens.db')))

@contextmanager
def db():
    path = database_path()
    path.parent.mkdir(parents=True,exist_ok=True)
    conn=sqlite3.connect(path,timeout=10)
    conn.row_factory=sqlite3.Row
    conn.execute('PRAGMA foreign_keys=ON')
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    with db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE NOT NULL,role TEXT NOT NULL,password_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,timestamp TEXT NOT NULL,event_type TEXT NOT NULL,action TEXT NOT NULL,source_ip TEXT NOT NULL DEFAULT '',actor TEXT NOT NULL DEFAULT '',geo_label TEXT NOT NULL DEFAULT '',process TEXT NOT NULL DEFAULT '',destination TEXT NOT NULL DEFAULT '',summary TEXT NOT NULL DEFAULT '',severity TEXT NOT NULL DEFAULT 'info');
        CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
        CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,rule_id TEXT NOT NULL,event_id INTEGER NOT NULL REFERENCES events(id),severity TEXT NOT NULL,title TEXT NOT NULL,technique TEXT NOT NULL,reason TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'new',owner TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,UNIQUE(rule_id,event_id));
        CREATE TABLE IF NOT EXISTS cases(id INTEGER PRIMARY KEY,title TEXT NOT NULL,status TEXT NOT NULL DEFAULT 'open',severity TEXT NOT NULL DEFAULT 'medium',assignee TEXT NOT NULL DEFAULT '',notes TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS case_alerts(case_id INTEGER REFERENCES cases(id),alert_id INTEGER REFERENCES alerts(id),PRIMARY KEY(case_id,alert_id));
        CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,actor TEXT NOT NULL,action TEXT NOT NULL,object_id INTEGER,created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        """)
