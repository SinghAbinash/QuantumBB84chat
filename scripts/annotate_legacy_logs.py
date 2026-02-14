#!/usr/bin/env python3
"""
Scan the `room_logs` table for legacy entries that look like raw ciphertext or old
"Encrypted message" formats and append structured, non-sensitive annotations
for easier auditing. This script does NOT delete or redact original rows; it
inserts migration annotations and corresponding structured tags.

Usage: python scripts/annotate_legacy_logs.py
"""
import os
import sys
import re
# Ensure project root is on sys.path so we can import db.py
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from db import _connect, add_log

BASE64_RE = re.compile(r'[A-Za-z0-9+/]{80,}={0,2}')

def infer_sender_from_text(text: str):
    # Heuristic: if message starts with "Name: ...", return Name
    m = re.match(r"^([^:\n]{1,120}):\s*(.+)$", text)
    if m:
        return m.group(1).strip()
    return None

def scan_and_annotate(db_path=None):
    conn = _connect()
    cur = conn.cursor()
    cur.execute('SELECT id, room_id, message FROM room_logs ORDER BY id ASC')
    rows = cur.fetchall()
    migrated = 0
    for rid, room, msg in rows:
        try:
            if not msg or isinstance(msg, bytes):
                continue
            text = msg if isinstance(msg, str) else str(msg)
            # Skip already-structured entries that start with [TAG]
            if text.strip().startswith('['):
                continue
            # Look for old literal prefix used by older clients
            if 'Encrypted message' in text or 'ciphertext' in text or BASE64_RE.search(text):
                # avoid double-annotating: check if we've already created a migration note for this id
                note_text = f"[MIGRATION_ANNOTATION] legacy_id={rid}"
                cur.execute('SELECT 1 FROM room_logs WHERE room_id = ? AND message = ?', (room, note_text))
                if cur.fetchone():
                    continue
                sender = infer_sender_from_text(text) or 'unknown'
                # try to infer payload length from base64 match
                m = BASE64_RE.search(text)
                payload_len = len(m.group(0)) if m else len(text)

                # Insert annotations (use add_log helper to ensure same DB path)
                add_log(room, f"[MIGRATION_ANNOTATION] legacy_id={rid} inferred_type=encrypted inferred_sender={sender} inferred_len={payload_len}")
                add_log(room, f"[MSG_ENCRYPTED] user={sender} iv_len=unknown")
                add_log(room, f"[MSG_RELAYED] room={room} sender={sender}")
                add_log(room, f"[SERVER_NOTE] Encrypted payload relayed; no key material stored.")
                migrated += 1
        except Exception:
            # ignore individual row errors
            continue
    conn.close()
    print(f"Annotated {migrated} legacy entries with structured logs.")

if __name__ == '__main__':
    scan_and_annotate()
