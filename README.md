# Quantum-Random AES Chat (prototype)

This prototype demonstrates using IBM/Qiskit-generated randomness to create an AES-256 session key
which is then securely shared to clients using RSA. After the session key is exchanged, clients send
AES-encrypted messages via WebSockets.

Contents:
- `server.py` — Flask + SocketIO server (room management, quantum key generation, RSA-encrypted key delivery)
- `quantum.py` — module that attempts to use IBM Quantum or Qiskit Aer, falls back to OS RNG
- `crypto_utils.py` — helpers to encrypt room AES key (accepts browser SPKI public key b64) and AES-GCM helpers
- `static/client.html` — browser demo using WebCrypto to generate RSA key pair and receive encrypted session key
- `requirements.txt` — Python dependencies

Quickstart
1. Create a Python virtualenv and install deps:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

2. (Optional) To use real IBM Quantum, set `IBM_QUANTUM_TOKEN` environment variable and install `qiskit-ibm-runtime`.

3. Run the server:

```powershell
python server.py
```

4. Open `http://localhost:5000/` in two browsers (or tabs). Join same room. The server will request quantum randomness,
   derive a 256-bit AES key, and encrypt it with each client's RSA public key. Clients will decrypt the session key
   locally and can send AES-encrypted messages.

Security notes
- This is a prototype. For production you should:
  - Use TLS for all transport (WSS/HTTPS).
  - Prefer ephemeral ECDH (X25519) for forward secrecy instead of long-lived RSA keys.
  - Keep the server from storing plain session keys; consider performing key agreement client-to-client.
