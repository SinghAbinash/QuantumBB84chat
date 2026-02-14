#!/usr/bin/env python3
"""CLI to view and follow per-room logs stored in the local SQLite DB.

Usage:
    python room_logs.py --room testroom --limit 20
    python room_logs.py --room testroom --follow

This script reads logs from the `room_logs` table created by `db.init_db()`
and prints formatted entries including timestamps and a simple local summary.
"""
import argparse
import time
from typing import List
import os
from datetime import datetime, timezone, timedelta

from db import init_db, get_logs


def format_to_ist(iso: str) -> str:
    """Convert ISO timestamp string to IST (UTC+5:30) formatted as YYYY-MM-DD HH:MM:SS"""
    if not iso:
        return ''
    try:
        # Handle trailing Z (UTC) and naive timestamps
        s = iso
        if s.endswith('Z'):
            s = s.replace('Z', '+00:00')
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        ist = dt.astimezone(timezone(timedelta(hours=5, minutes=30)))
        return ist.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return iso


def _load_dotenv(path: str = '.env'):
    """Lightweight .env loader: set variables into os.environ if not already set."""
    if not os.path.exists(path):
        return
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for ln in f:
                ln = ln.strip()
                if not ln or ln.startswith('#'):
                    continue
                if '=' not in ln:
                    continue
                k, v = ln.split('=', 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and (k not in os.environ):
                    os.environ[k] = v
    except Exception:
        # silently continue; this is just convenience for local dev
        pass


# load .env early so users can store GOOGLE_API_KEY / GEMINI_ENDPOINT locally
_load_dotenv()


# Gemini/Generative API support removed — use local heuristic summary only.


def print_logs(room: str, limit: int = 100):
    logs = get_logs(room, limit=limit)
    if not logs:
        print(f'No logs for room: {room}')
        return
    for l in logs:
        ts = l.get('created_at') or ''
        msg = l.get('message') or ''
        print(f'[{format_to_ist(ts)}]')
        print(msg)
        print('-' * 72)

    # Run analysis on the concatenated logs
    concat = '\n\n'.join(f"[{l.get('created_at')}]\n{l.get('message')}" for l in logs)
    analysis = _simple_log_summary(concat)
    print('\nANALYSIS:\n')
    print(analysis)


def follow(room: str, poll: float = 2.0):
    last_seen = 0
    while True:
        logs = get_logs(room, limit=1000)
        # get newest id by counting
        if logs:
            # logs returned chronological; pick new ones
            new = logs[last_seen:]
            for l in new:
                ts = l.get('created_at') or ''
                print(f"[{format_to_ist(ts)}]\n{l.get('message')}\n")
            last_seen = len(logs)
        else:
            if last_seen == 0:
                # show header once
                print(f'No logs yet for room: {room}')

        # periodically produce a short analysis of recent logs
        if len(logs) > 0:
            concat = '\n\n'.join(f"[{l.get('created_at')}]\n{l.get('message')}" for l in logs[-10:])
            analysis = _simple_log_summary(concat)
            print('\nANALYSIS (latest):\n')
            print(analysis)
        time.sleep(poll)


# Gemini analysis removed; rely on local `_simple_log_summary` defined below.


def _simple_log_summary(text: str) -> str:
    # Parse structured tags like:
    # [ROOM_CREATED] room=abc123 leader=Alice expected=3
    # [BB84_INIT] from=Alice to=Bob length=128
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    events = {}

    def parse_kv(s: str):
        out = {}
        for part in s.split():
            if '=' in part:
                k, v = part.split('=', 1)
                out[k] = v
        return out

    for ln in lines:
        if ln.startswith('['):
            # extract tag and remainder
            try:
                tag_end = ln.index(']')
                tag = ln[1:tag_end]
                rest = ln[tag_end+1:].strip()
                kv = parse_kv(rest)
                events.setdefault(tag, []).append(kv)
            except Exception:
                # non-conforming line; treat as misc
                events.setdefault('MISC', []).append({'line': ln})
        else:
            events.setdefault('MISC', []).append({'line': ln})

    out_lines = []
    out_lines.append(f'Total structured events parsed: {sum(len(v) for v in events.values())}')

    # Room lifecycle
    if 'ROOM_CREATED' in events:
        for e in events['ROOM_CREATED']:
            out_lines.append(f"Room created: room={e.get('room')} leader={e.get('leader')} expected={e.get('expected')}")
    if 'USER_JOIN' in events:
        joins = [e.get('user') for e in events['USER_JOIN'] if e.get('user')]
        out_lines.append(f"Users joined ({len(joins)}): {', '.join(joins)}")
    if 'ROOM_READY' in events:
        for e in events['ROOM_READY']:
            out_lines.append(f"Room ready: room={e.get('room')} members={e.get('members')}")

    # BB84 metadata
    if 'BB84_INIT' in events or 'BB84_SIFTING_COMPLETE' in events or 'BB84_SESSION_DERIVED' in events:
        out_lines.append('BB84 events:')
        for e in events.get('BB84_INIT', []):
            out_lines.append(f" - INIT: from={e.get('from')} to={e.get('to')} length={e.get('length')}")
        for e in events.get('BB84_SIFTING_COMPLETE', []):
            out_lines.append(f" - SIFTING_COMPLETE: matched_bits={e.get('matched_bits', 'unknown')}")
        for e in events.get('BB84_SESSION_DERIVED', []):
            out_lines.append(f" - SESSION_DERIVED: from={e.get('from')} to={e.get('to')} key_length={e.get('key_length')}")

    # Room key lifecycle
    if 'ROOMKEY_GENERATED' in events or 'ROOMKEY_ENCRYPTED' in events or 'ROOMKEY_RELAYED' in events or 'ROOMKEY_DECRYPTED' in events:
        out_lines.append('Room key events:')
        for e in events.get('ROOMKEY_GENERATED', []):
            out_lines.append(f" - GENERATED: by={e.get('by')} size={e.get('size')}")
        for e in events.get('ROOMKEY_ENCRYPTED', []):
            out_lines.append(f" - ENCRYPTED: to={e.get('to')} method={e.get('method')}")
        for e in events.get('ROOMKEY_RELAYED', []):
            out_lines.append(f" - RELAYED: from={e.get('from')} to={e.get('to')} ciphertext_len={e.get('ciphertext_len')}")
        for e in events.get('ROOMKEY_DECRYPTED', []):
            out_lines.append(f" - DECRYPTED: user={e.get('user')}")

    # Encrypted messaging flow
    if 'MSG_ENCRYPTED' in events or 'MSG_RELAYED' in events or 'MSG_DECRYPTED' in events:
        out_lines.append('Encrypted messaging:')
        for e in events.get('MSG_ENCRYPTED', []):
            out_lines.append(f" - MSG_ENCRYPTED: user={e.get('user')} iv_len={e.get('iv_len')}")
        for e in events.get('MSG_RELAYED', []):
            out_lines.append(f" - MSG_RELAYED: room={e.get('room')} sender={e.get('sender')}")
        for e in events.get('MSG_DECRYPTED', []):
            out_lines.append(f" - MSG_DECRYPTED: user={e.get('user')}")

    # Key destruction and termination
    if 'ROOM_TERMINATED' in events:
        out_lines.append('Room termination events:')
        for e in events.get('ROOM_TERMINATED', []):
            out_lines.append(f" - ROOM_TERMINATED: room={e.get('room')}")
    if 'KEY_DESTROYED' in events:
        destroyed = [e.get('user') for e in events['KEY_DESTROYED'] if e.get('user')]
        out_lines.append(f"Keys destroyed for users ({len(destroyed)}): {', '.join(destroyed)}")

    # Server notes
    if 'SERVER_NOTE' in events:
        out_lines.append('Server notes:')
        for e in events.get('SERVER_NOTE', []):
            # message stored after tag in legacy logs
            line = 'Encrypted payload relayed; no key material stored.'
            out_lines.append(f" - {line}")

    if not out_lines:
        return 'No protocol-specific entries found in recent logs.'
    return '\n'.join(out_lines)


def main(argv: List[str] = None):
    parser = argparse.ArgumentParser(description='View room logs')
    parser.add_argument('--room', '-r', required=True, help='Room id to show logs for')
    parser.add_argument('--limit', '-n', type=int, default=100, help='Number of recent logs to show')
    parser.add_argument('--follow', '-f', action='store_true', help='Follow logs (tail -f style)')
    parser.add_argument('--init-db', action='store_true', help='Initialize DB if missing')
    args = parser.parse_args(argv)

    if args.init_db:
        p = init_db()
        print(f'Initialized DB at {os.path.abspath(p)}')

    if args.follow:
        follow(args.room)
    else:
        print_logs(args.room, limit=args.limit)


if __name__ == '__main__':
    main()
