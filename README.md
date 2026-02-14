# QSEC — QuantumBB84chat 

This prototype demonstrates an end-to-end encrypted chat where the server acts as a relay and room/metadata
manager while clients handle key generation, key exchange, and message encryption.

Key points:
- The server (`server.py` + `chatcontainer.py`) manages rooms, forwards public keys and encrypted payloads,
  relays BB84/QKD messages between peers, and stores structured metadata/logs.
- Clients are responsible for generating session keys (or performing QKD via BB84), encrypting room keys for peers,
  and decrypting messages locally. The server never decrypts client ciphertexts and does not persist plaintext keys.

Contents:
- `server.py` — Flask + SocketIO application that exposes the web UI and runs the Socket.IO server.
- `chatcontainer.py` — Socket.IO handlers: room membership, pubkey announcements, relays for `roomkey_share`, `bb84_relay`,
  encrypted message forwarding, and structured room logs.
- `db.py` — SQLite-backed helpers to persist room logs, users, and optional room key blobs (used only for metadata/storage).
- `qber_analysis.py` — helpers to analyze BB84/QBER related data (sampling, mismatch/QBER computation).
- `static/` — client UI and JS (`client.html`, `room.html`, `room.js`) demonstrating the browser-side flows.
- `tests/` — simple test tools and simulators (e.g. `sim_clients.py`).
- `requirements.txt` — Python dependencies.

Quickstart
1. Create a Python virtualenv and install dependencies (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. Run the server:

```powershell
python server.py
```

3. Open `http://localhost:5000/` (or open a room at `http://localhost:5000/room/<room_id>`) in two browsers or tabs.
   Clients publish their public keys to the server and then perform client-to-client encrypted key exchange (or QKD)
   via the provided Socket.IO messages. The server will relay encrypted room keys and encrypted messages but will not
   decrypt or store key material.

Behavior notes
- The server logs structured events to the SQLite database in `data/qsec2.db` (room creation, joins, metadata about
  encrypted messages and key relays). It intentionally avoids storing ciphertexts or secret key material.
- The repository includes a lightweight BB84 metadata relay and analysis helpers (`qber_analysis.py`) so clients can
  perform QKD-style exchanges and log non-sensitive summary metrics (e.g., QBER) for diagnostics.







