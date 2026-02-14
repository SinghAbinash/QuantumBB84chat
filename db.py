import os
import sqlite3
from typing import Dict, List, Optional

DB_PATH = os.environ.get('QSEC2_DB', os.path.join('data', 'qsec2.db'))


def init_db(db_path: Optional[str] = None):
    path = db_path or DB_PATH
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path)
    cur = conn.cursor()
    cur.execute('''
    CREATE TABLE IF NOT EXISTS rooms (
        room_id TEXT PRIMARY KEY,
        key BLOB
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS room_users (
        room_id TEXT,
        username TEXT,
        UNIQUE(room_id, username)
    )
    ''')
    cur.execute('''
    CREATE TABLE IF NOT EXISTS room_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        room_id TEXT,
        message TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    ''')
    conn.commit()
    conn.close()
    return path


def _connect():
    return sqlite3.connect(DB_PATH)


def set_room_key(room: str, key: bytes):
    conn = _connect()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO rooms(room_id, key) VALUES (?, ?)', (room, key))
    conn.commit()
    conn.close()


def get_room_key(room: str) -> Optional[bytes]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT key FROM rooms WHERE room_id = ?', (room,))
    r = cur.fetchone()
    conn.close()
    return r[0] if r else None


def get_all_room_keys() -> Dict[str, bytes]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT room_id, key FROM rooms')
    out = {row[0]: row[1] for row in cur.fetchall()}
    conn.close()
    return out


def add_user(room: str, username: str):
    conn = _connect()
    cur = conn.cursor()
    try:
        cur.execute('INSERT OR IGNORE INTO room_users(room_id, username) VALUES (?, ?)', (room, username))
        conn.commit()
    finally:
        conn.close()


def add_log(room: str, message: str):
    conn = _connect()
    cur = conn.cursor()
    cur.execute('INSERT INTO room_logs(room_id, message) VALUES (?, ?)', (room, message))
    conn.commit()
    rowid = cur.lastrowid
    # fetch the inserted row to return structured info
    cur.execute('SELECT id, message, created_at FROM room_logs WHERE id = ?', (rowid,))
    r = cur.fetchone()
    conn.close()
    if r:
        return {'id': r[0], 'message': r[1], 'created_at': r[2]}
    return None


def get_logs(room: str, limit: int = 100, since_id: int = None):
    conn = _connect()
    cur = conn.cursor()
    if since_id is None:
        cur.execute('SELECT id, message, created_at FROM room_logs WHERE room_id = ? ORDER BY id DESC LIMIT ?', (room, limit))
    else:
        cur.execute('SELECT id, message, created_at FROM room_logs WHERE room_id = ? AND id > ? ORDER BY id DESC LIMIT ?', (room, since_id, limit))
    rows = cur.fetchall()
    conn.close()
    # Return in chronological order (oldest first) and include id
    return [{'id': r[0], 'message': r[1], 'created_at': r[2]} for r in reversed(rows)]


def remove_user(room: str, username: str):
    conn = _connect()
    cur = conn.cursor()
    cur.execute('DELETE FROM room_users WHERE room_id = ? AND username = ?', (room, username))
    conn.commit()
    conn.close()


def get_users(room: str) -> List[str]:
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT username FROM room_users WHERE room_id = ?', (room,))
    rows = [r[0] for r in cur.fetchall()]
    conn.close()
    return rows
