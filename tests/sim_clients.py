import socketio
import threading
import time
import base64
import os

SERVER = 'http://127.0.0.1:5000'
ROOM = 'o6bj8my'

clients = {}
received = {}

def make_client(name):
    sio = socketio.Client()

    @sio.event
    def connect():
        print(f"[{name}] connected")
        sio.emit('join', {'room': ROOM, 'username': name})

    @sio.on('joined')
    def on_joined(d):
        print(f"[{name}] joined room")

    @sio.on('group_message')
    def on_group(d):
        print(f"[{name}] received group_message: {d.get('from')} -> payload keys: {list(d.keys())}")
        received.setdefault(name, []).append(d)

    @sio.on('encrypted_message')
    def on_enc(d):
        print(f"[{name}] received encrypted_message event")
        received.setdefault(name, []).append(('encrypted_message', d))

    @sio.event
    def disconnect():
        print(f"[{name}] disconnected")

    return sio

# Start clients
names = ['A', 'B', 'C']
threads = []
for n in names:
    sio = make_client(n)
    clients[n] = sio
    t = threading.Thread(target=lambda s=sio: s.connect(SERVER, transports=['websocket', 'polling']))
    t.daemon = True
    t.start()
    threads.append(t)
    time.sleep(0.25)

# Wait for connections
time.sleep(2)

# Send a group_message from A
iv = os.urandom(12)
ct = b'hello-ct-bytes'
iv_b64 = base64.b64encode(iv).decode()
ct_b64 = base64.b64encode(ct).decode()
print('[TEST] A sending relay group_message')
clients['A'].emit('relay', {'type':'group_message','room':ROOM,'from':'A','ciphertext':ct_b64,'iv':iv_b64})

# Wait to receive
time.sleep(1)

print('\n=== Receipt summary ===')
for n in names:
    rec = received.get(n, [])
    print(f"{n}: got {len(rec)} messages")

# Now simulate leadership change: make B 'leader' by reordering join (disconnect and reconnect B as first)
print('\n[TEST] Simulating leadership change: reconnect B as new leader')
clients['B'].disconnect()
# wait
time.sleep(0.5)
# reconnect B (simulate becoming first by reconnecting quickly)
clients['B'] = make_client('B')
clients['B'].connect(SERVER)
time.sleep(1)

# B sends another message
iv2 = os.urandom(12)
ct2 = b'hello-from-B'
iv2_b64 = base64.b64encode(iv2).decode()
ct2_b64 = base64.b64encode(ct2).decode()
print('[TEST] B sending relay group_message')
clients['B'].emit('relay', {'type':'group_message','room':ROOM,'from':'B','ciphertext':ct2_b64,'iv':iv2_b64})

time.sleep(1)
print('\n=== Receipt summary after B message ===')
for n in names:
    rec = received.get(n, [])
    print(f"{n}: got {len(rec)} messages")

# Clean up
for s in list(clients.values()):
    try: s.disconnect()
    except: pass

print('Done')
