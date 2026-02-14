// Initialize Socket.IO client and add diagnostic logging
      const socket = (typeof io === 'function') ? io() : null;
      if (!socket) console.error('Socket.IO client not found (io is undefined)');
      else {
        socket.on('connect', () => console.log('socket connected', socket.id));
        socket.on('connect_error', (err) => console.error('socket connect_error', err));
        socket.on('disconnect', (reason) => console.log('socket disconnected', reason));
      }
      const params = new URLSearchParams(window.location.search);
      const username = params.get('username') || 'guest';
      const room = window.location.pathname.split('/').pop();
      document.getElementById('roomValue').innerText = room;
      document.getElementById('senderName').innerText = username;
      let aesKey = null;
      // Snapshot of the group's AES raw key (base64) captured at join time
      let joinGroupKeyRawB64 = null;
      // Queue for incoming ciphertexts received before AES room key is available
      let incomingCipherQueue = [];
      // Ciphertexts replayed from persisted DB logs for chat history
      let persistedCipherHistory = [];
      const seenCiphertexts = new Set();
      // Map ciphertext -> placeholder DOM element for queued encrypted messages
      const placeholderMap = {};
      let summaryTimer = null;
      let pendingAttachment = null;
      const MAX_FILE_BYTES = 8 * 1024 * 1024;
      const B64_CHUNK = 0x8000;
      const FULLSCREEN_PREF_KEY = 'chat-fullscreen-pref';

      // Cross-browser subtle crypto reference (handles webkit/ms prefixed variants)
      const subtleCrypto = (window.crypto && (window.crypto.subtle || window.crypto.webkitSubtle)) || (window.msCrypto && window.msCrypto.subtle) || null;

      function applyChatFullscreen(enabled) {
        document.body.classList.toggle('chat-fullscreen', enabled);
        // also mark 'in-fullscreen' so header hides when chat is maximized
        document.body.classList.toggle('in-fullscreen', enabled);
        const btn = document.getElementById('fullscreenToggle');
        const path = document.getElementById('fullscreenIconPath');
        if (enabled) {
          path.setAttribute('d', 'M9 3H3v6M15 3h6v6M3 15v6h6M21 15v6h-6');
          btn.setAttribute('aria-label', 'Minimize chat');
          btn.setAttribute('title', 'Minimize chat');
        } else {
          path.setAttribute('d', 'M8 3H3v5M16 3h5v5M8 21H3v-5M21 16v5h-5');
          btn.setAttribute('aria-label', 'Maximize chat');
          btn.setAttribute('title', 'Maximize chat');
        }
        btn.setAttribute('aria-pressed', enabled ? 'true' : 'false');
        try { localStorage.setItem(FULLSCREEN_PREF_KEY, enabled ? '1' : '0'); } catch (_) {}
      }

      function parseTs(ts) {
        const t = Date.parse(ts || '');
        return Number.isNaN(t) ? 0 : t;
      }

      // Format timestamp in fixed Indian Standard Time (Asia/Kolkata): YYYY-MM-DD HH:MM:SS
      const IST_FORMATTER = new Intl.DateTimeFormat('en-CA', {
        timeZone: 'Asia/Kolkata',
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
      });

      socket.on('plain_message', (d) => {
        try{
          if (!d || d.room !== room) return;
          const from = d.from || 'unknown';
          const to = d.to || 'ALL';
          const msg = d.message || '';
          const envelope = { type: 'text', text: msg, ts: d.ts || new Date().toISOString() };
          renderMessage(from, to, envelope, from === username, envelope.ts);
        }catch(e){ console.error('plain_message handler failed', e); }
      });

      function formatToIST(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        if (Number.isNaN(d.getTime())) return String(iso);
        const parts = IST_FORMATTER.formatToParts(d);
        const map = {};
        for (const p of parts) {
          if (p.type !== 'literal') map[p.type] = p.value;
        }
        return `${map.year}-${map.month}-${map.day} ${map.hour}:${map.minute}:${map.second}`;
      }

      function bytesToBase64(bytes) {
        let binary = '';
        for (let i = 0; i < bytes.length; i += B64_CHUNK) {
          const chunk = bytes.subarray(i, i + B64_CHUNK);
          binary += String.fromCharCode.apply(null, chunk);
        }
        return btoa(binary);
      }

      function base64ToBytes(b64) {
        const binary = atob(b64);
        const out = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
        return out;
      }

      function arrayBufferToBase64(buf) {
        return bytesToBase64(new Uint8Array(buf));
      }

      function base64ToArrayBuffer(b64) {
        const u8 = base64ToBytes(b64);
        return u8.buffer.slice(u8.byteOffset, u8.byteOffset + u8.byteLength);
      }


      async function initiateQke() {
        if (!window.crypto || !window.crypto.subtle) throw new Error('WebCrypto not available');
        try{
          // generate ephemeral ECDH keypair (P-256)
          const kp = await window.crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
          window._qke_priv = kp.privateKey;
          const pubRaw = await window.crypto.subtle.exportKey('raw', kp.publicKey);
          const pubB64 = arrayBufferToBase64(pubRaw);
          try{ socket.emit('qke_init', { room, client_pub: pubB64 }); }catch(e){ console.error('qke_init emit failed', e); }
        }catch(e){ console.error('initiateQke failed', e); throw e; }
      }

      socket.on('qke_response', async (d) => {
        try{
          if (!d || !d.server_pub || !d.encrypted_room_key || !d.iv) return;
          if (!window._qke_priv) {
            console.warn('No ephemeral private key for QKE response');
            return;
          }
          const serverPubBuf = base64ToArrayBuffer(d.server_pub);
          const encRoomKeyBuf = base64ToArrayBuffer(d.encrypted_room_key);
          const ivBuf = base64ToArrayBuffer(d.iv);

          // import server public key
          const serverPub = await window.crypto.subtle.importKey('raw', serverPubBuf, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
          // derive shared secret (ArrayBuffer)
          const shared = await window.crypto.subtle.deriveBits({ name: 'ECDH', public: serverPub }, window._qke_priv, 256);
          // derive AES key via HKDF to match server HKDF output
          const baseKey = await window.crypto.subtle.importKey('raw', shared, { name: 'HKDF' }, false, ['deriveKey']);
          const info = new TextEncoder().encode('room-key-transfer');
          const salt = new Uint8Array([]);
          const derivedKey = await window.crypto.subtle.deriveKey({ name: 'HKDF', hash: 'SHA-256', salt, info }, baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']);

          // decrypt room key
          const plainRoomKeyBuf = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(ivBuf) }, derivedKey, encRoomKeyBuf);
          // import room key as AES-GCM CryptoKey for messaging
          aesKey = await window.crypto.subtle.importKey('raw', plainRoomKeyBuf, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
          // cleanup ephemeral private
          try{ window._qke_priv = null; }catch(e){}
          // notify that group key is ready
          window.dispatchEvent(new Event('groupKeyReady'));
          // update UI
          try{ document.getElementById('sessionStatus').innerText = 'Group key'; document.getElementById('send').disabled = false; }catch(e){}
        }catch(e){ console.error('qke_response handling failed', e); }
      });
      // handle published public key list from server
      socket.on('pubkey_list', async (d) => {
        try{
          window.peerPubKeys = (d && d.pubkeys) || {};
          // if we're the leader, try to distribute room key
          tryDistributeRoomKeyIfLeader().catch(e=>console.error('distribute attempt failed', e));
        }catch(e){ console.error('pubkey_list handler failed', e); }
      });

      // handle incoming encrypted room key shares from leader
      socket.on('roomkey_share', async (d) => {
        try{
          if (!d || !d.ciphertext) return;
          if (!window._rsa || !window._rsa.kp) { console.warn('no rsa private key to decrypt roomkey'); return; }
          const ct = base64ToArrayBuffer(d.ciphertext);
          const plain = await window.crypto.subtle.decrypt({ name: 'RSA-OAEP' }, window._rsa.kp.privateKey, ct);
          // import as AES-GCM key
          aesKey = await window.crypto.subtle.importKey('raw', plain, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
          try{ document.getElementById('sessionStatus').innerText = 'Group key (leader share)'; document.getElementById('send').disabled = false; }catch(e){}
          window.dispatchEvent(new Event('groupKeyReady'));
        }catch(e){ console.error('roomkey_share handler failed', e); }
      });

      // Encryption/channel helpers are loaded from external modules when available.

      async function encryptPacket(packet) {
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const plain = new TextEncoder().encode(JSON.stringify(packet));
        const enc = await window.crypto.subtle.encrypt({name:'AES-GCM', iv}, aesKey, plain);
        const combined = new Uint8Array(iv.byteLength + enc.byteLength);
        combined.set(iv, 0);
        combined.set(new Uint8Array(enc), iv.byteLength);
        return bytesToBase64(combined);
      }

      async function decryptPacket(payloadB64) {
        const arr = base64ToBytes(payloadB64);
        const iv = arr.slice(0, 12);
        const ct = arr.slice(12);
        const plainBuf = await window.crypto.subtle.decrypt({name:'AES-GCM', iv}, aesKey, ct);
        const text = new TextDecoder().decode(plainBuf);
        try {
          const parsed = JSON.parse(text);
          if (parsed && typeof parsed === 'object') return parsed;
        } catch (_) {}
        return {
          v: 1,
          kind: 'chat',
          from: 'unknown',
          to: 'ALL',
          ts: new Date().toISOString(),
          envelope: { type: 'text', text }
        };
      }
      // Attempt to process any queued ciphertexts (called when aesKey becomes available)
      
      // Attempt to process any queued ciphertexts (called when aesKey becomes available)
      async function decryptWithKey(payloadB64, key) {
        const arr = base64ToBytes(payloadB64);
        const iv = arr.slice(0, 12);
        const ct = arr.slice(12);
        const plainBuf = await window.crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
        const text = new TextDecoder().decode(plainBuf);
        try{ return JSON.parse(text); }catch(_){ return { v:1, kind:'chat', from:'unknown', to:'ALL', ts:new Date().toISOString(), envelope:{ type:'text', text } }; }
      }

      async function processIncomingQueue() {
        if ((!aesKey && !(window.pairwiseKeys && window.pairwiseKeys['__group__'])) || incomingCipherQueue.length === 0) return;
        const queue = incomingCipherQueue.slice();
        incomingCipherQueue = [];
        for (const entry of queue) {
          const ciphertext = entry.ciphertext || entry.payload || '';
          if (!ciphertext || seenCiphertexts.has(ciphertext)) continue;
          try {
            let packet = null;
            try{ packet = await decryptPacket(ciphertext); }catch(e){
              // try group key decryption if available
              const gk = (window.pairwiseKeys && window.pairwiseKeys['__group__']);
              if(gk) packet = await decryptWithKey(ciphertext, gk);
              else throw e;
            }
            if (!packet || packet.kind !== 'chat') continue;
            const to = packet.to || 'ALL';
            const from = packet.from || 'unknown';
            if (!(to === 'ALL' || to === username || from === username)) continue;
            const envelope = packet.envelope || { type: 'text', text: '' };
            seenCiphertexts.add(ciphertext);
            // remove placeholder if present
            try{ const ph = placeholderMap[ciphertext]; if(ph){ ph.remove(); delete placeholderMap[ciphertext]; } }catch(e){}
            renderMessage(from, to, envelope, from === username, packet.ts || (envelope && envelope.ts));
          } catch (e) {
            console.error('Queued decrypt failed', e);
          }
        }
      }

      async function processPersistedCipherHistory() {
        if ((!aesKey && !(window.pairwiseKeys && window.pairwiseKeys['__group__'])) || persistedCipherHistory.length === 0) return;
        const queue = persistedCipherHistory.slice();
        persistedCipherHistory = [];
        for (const entry of queue) {
          const ciphertext = entry.ciphertext || '';
          if (!ciphertext || seenCiphertexts.has(ciphertext)) continue;
          try {
            let packet = null;
            try{ packet = await decryptPacket(ciphertext); }catch(e){
              const gk = (window.pairwiseKeys && window.pairwiseKeys['__group__']);
              if(gk) packet = await decryptWithKey(ciphertext, gk);
              else throw e;
            }
            if (!packet || packet.kind !== 'chat') continue;
            const to = packet.to || 'ALL';
            const from = packet.from || 'unknown';
            if (!(to === 'ALL' || to === username || from === username)) continue;
            const envelope = packet.envelope || { type: 'text', text: '' };
            seenCiphertexts.add(ciphertext);
            try{ const ph = placeholderMap[ciphertext]; if(ph){ ph.remove(); delete placeholderMap[ciphertext]; } }catch(e){}
            renderMessage(from, to, envelope, from === username, packet.ts || (envelope && envelope.ts) || entry.created_at);
          } catch (e) {
            console.error('Persisted chat decrypt failed', e);
          }
        }
      }

      function formatBytes(n) {
        if (!Number.isFinite(n) || n <= 0) return '0 B';
        const units = ['B', 'KB', 'MB', 'GB'];
        const p = Math.min(Math.floor(Math.log(n) / Math.log(1024)), units.length - 1);
        const val = n / Math.pow(1024, p);
        return `${val.toFixed(val < 10 && p > 0 ? 1 : 0)} ${units[p]}`;
      }

      // BB84 stats helpers: update/reset the BB84 Session Statistics panel
      function setBB84Stats(stats) {
        try{
          const el = id => document.getElementById(id);
          if(el('bb84_original_bits')) el('bb84_original_bits').innerText = (stats.original_bits !== null && stats.original_bits !== undefined) ? String(stats.original_bits) : '-';
          if(el('bb84_matched_bits')) el('bb84_matched_bits').innerText = (stats.matched_bits !== null && stats.matched_bits !== undefined) ? String(stats.matched_bits) : '-';
          if(el('bb84_mismatched_bits')) el('bb84_mismatched_bits').innerText = (stats.mismatched_bits !== null && stats.mismatched_bits !== undefined) ? String(stats.mismatched_bits) : '-';
          if(el('bb84_qber')) el('bb84_qber').innerText = (stats.qber !== null && stats.qber !== undefined) ? ((stats.qber * 100).toFixed(2) + '%') : '-';
          const threshold = 0.11;
          if(el('bb84_threshold')) el('bb84_threshold').innerText = (threshold * 100).toFixed(0) + '%';
          if(el('bb84_status')){
            const q = stats.qber;
            const st = (q !== null && q !== undefined && !Number.isNaN(q)) ? ((q <= threshold) ? '✔ Accepted' : '✖ Rejected') : '-';
            el('bb84_status').innerText = st;
          }
        }catch(e){ console.error('setBB84Stats failed', e); }
      }

      function resetBB84Stats(){
        setBB84Stats({ original_bits: null, matched_bits: null, mismatched_bits: null, qber: null });
      }

      // expose to global for manual testing
      window.setBB84Stats = setBB84Stats;
      window.resetBB84Stats = resetBB84Stats;

      async function renderMessage(from, to, envelope, isSelf, ts) {
        const logEl = document.getElementById('log');
        const item = document.createElement('div');
        // Use theme classes so CSS can control colors across themes
        item.className = `mb-2 rounded-lg border px-3 py-2 ${isSelf ? 'msg-self' : 'msg-other'}`;

        const meta = document.createElement('div');
        meta.className = 'mb-1 text-xs msg-meta';
        const timeText = ts ? ` · ${formatToIST(ts)}` : '';
        meta.textContent = `${from} -> ${to}${timeText}`;
        item.appendChild(meta);

        const body = document.createElement('div');
        body.className = 'whitespace-pre-wrap break-words text-sm msg-body';

        if (envelope.type === 'file') {
          const wrap = document.createElement('div');
          wrap.className = 'flex flex-col gap-2';
          try {
            const mime = envelope.mime || 'application/octet-stream';
            const bytes = base64ToBytes(envelope.data_b64 || '');
            const blob = new Blob([bytes], { type: mime });
            const url = URL.createObjectURL(blob);
            const name = envelope.name || 'attachment';

            if (envelope.text) {
              const caption = document.createElement('div');
              caption.className = 'text-sm text-[#0c5b55]';
              caption.textContent = envelope.text;
              wrap.appendChild(caption);
            }

            const link = document.createElement('a');
            link.href = url;
            link.download = name;
            link.className = 'text-sm font-medium text-[#0f766e]';
            link.textContent = `${name} (${formatBytes(envelope.size || bytes.length)})`;
            wrap.appendChild(link);

            if (mime.startsWith('image/')) {
              const img = document.createElement('img');
              img.src = url;
              img.alt = name;
              img.className = 'max-w-full rounded-lg border border-[#d2dce7]';
              wrap.appendChild(img);
            } else if (mime.startsWith('video/')) {
              const video = document.createElement('video');
              video.src = url;
              video.controls = true;
              video.className = 'max-w-full rounded-lg border border-[#d2dce7] bg-black';
              wrap.appendChild(video);
            }
          } catch (e) {
            console.error('renderMessage file handling failed', e);
            const errDiv = document.createElement('div');
            errDiv.textContent = '⚠️ Failed to render attachment';
            wrap.appendChild(errDiv);
          }
          body.appendChild(wrap);
        } else {
          body.textContent = envelope.text || '';
        }

        item.appendChild(body);
        logEl.appendChild(item);
        logEl.scrollTop = logEl.scrollHeight;
      }

      // AI summary removed; keep scheduleSummaryRefresh as a no-op so existing calls are safe
      function scheduleSummaryRefresh(/* delayMs = 1200 */) {
        // no-op
      }

      // Peer-to-peer BB84 implementation (server only relays messages).
      // Each BB84 session is stored per-peer in `window.bb84_sessions`.
      window.bb84_sessions = window.bb84_sessions || {};
      window.isLeader = false;
      // Read expected users from URL query parameter `expected` (if present).
      try{
        const params = new URLSearchParams(window.location.search || '');
        const exp = parseInt(params.get('expected') || '') || null;
        window.expectedUsers = exp;
      }catch(e){ window.expectedUsers = null; }
      window.bb84_initiated = window.bb84_initiated || false;

      function randBitStr(n){
        let s = '';
        for(let i=0;i<n;i++) s += (Math.random() < 0.5) ? '0' : '1';
        return s;
      }

      // Initiate BB84 with a single peer
      async function sendBB84Prepare(to, num=128){
        const bits = randBitStr(num);
        const bases = randBitStr(num);
        window.bb84_sessions[to] = { role:'sender', bits, bases, num, to };
        try{ socket.emit('bb84_relay', { room, to, bb84_type: 'prepare', payload: { bits, bases, num } }); }catch(e){ console.error('bb84 prepare emit failed', e); }
      }

      // Called by leader to check if all pairwise session hashes are ready
      async function maybeLeaderFinalize(){
        try{
          if(!window.isLeader) return;
          const expected = window.expectedUsers || null;
          if(expected && Array.isArray(window.currentUsers) && window.currentUsers.length !== expected) return;
          const peers = (window.currentUsers || []).filter(u => u && u !== username);
          if(!peers || peers.length === 0) return;
          // ensure we have session_hash for each peer
          for(const p of peers){ const s = window.bb84_sessions[p]; if(!s || !s.session_hash) return; }
          if(window.leaderRoomKeyGenerated) return;
          // generate one room key and send encrypted copy to each peer
          const roomRaw = window.crypto.getRandomValues(new Uint8Array(32));
          // set local aesKey and snapshot
          aesKey = await window.crypto.subtle.importKey('raw', roomRaw, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
          try{ joinGroupKeyRawB64 = bytesToBase64(roomRaw); }catch(_){ joinGroupKeyRawB64 = null; }
          try{ document.getElementById('sessionStatus').innerText = 'Group key (BB84 generated)'; document.getElementById('send').disabled = false; }catch(e){}
          // Log and display the generated room key for the leader for debugging/verification
          try{
            // show a visible chat message in leader's own log indicating key generation
            try{
              // indicate non-sensitive info: leader created the RoomKey (do not display key material)
              try{ document.getElementById('sessionStatus').innerText = 'Room Key initiated'; }catch(e){}
            }catch(e){}
          }catch(e){ console.error('failed to surface leader room key', e); }
          window.dispatchEvent(new Event('groupKeyReady'));
          // notify server that leader generated the room key (no key material sent)
          try{ socket.emit('roomkey_generated', { room, by: username, size: 32, recipients: peers.length }); }catch(e){}
          // send encrypted room key to each peer
          for(const p of peers){
            try{
              const sessObj = window.bb84_sessions[p] || {};
              const hashBuf = sessObj.session_hash;
              if(!hashBuf) continue;
              const sessionKey = await window.crypto.subtle.importKey('raw', hashBuf, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
              const iv = window.crypto.getRandomValues(new Uint8Array(12));
              const ct = await window.crypto.subtle.encrypt({ name: 'AES-GCM', iv }, sessionKey, roomRaw);
              const combined = new Uint8Array(iv.byteLength + ct.byteLength);
              combined.set(iv,0); combined.set(new Uint8Array(ct), iv.byteLength);
              const combinedB64 = bytesToBase64(combined);
              try{ socket.emit('bb84_relay', { room, to: p, bb84_type: 'roomkey_enc', payload: { ciphertext: combinedB64 } }); }catch(e){ console.error('emit roomkey_enc failed', e); }
            }catch(e){ console.error('finalize send to peer failed', e); }
          }
          window.leaderRoomKeyGenerated = true;
        }catch(e){ console.error('maybeLeaderFinalize failed', e); }
      }

      // Derive session key from raw bits (string of '0'/'1')
      async function deriveSessionKeyFromRawBits(rawBits){
        const h = await window.crypto.subtle.digest('SHA-256', new TextEncoder().encode(rawBits));
        return h; // ArrayBuffer (32 bytes)
      }

      // Handle incoming BB84 messages relayed by server
      socket.on('bb84_message', async (d) => {
        try{
          if(!d || !d.bb84_type) return;
          const from = d.from;
          const t = d.bb84_type;
          const p = d.payload || {};
          if(t === 'prepare'){
            // receiver: generate random bases, perform simulated measurement, send client_bases back
            const serverBits = p.bits || '';
            const serverBases = p.bases || '';
            const num = p.num || serverBits.length;
            const clientBases = randBitStr(num);
            const measured = [];
            for(let i=0;i<num;i++){
              if(clientBases[i] === serverBases[i]) measured.push(serverBits[i]);
              else measured.push((Math.random() < 0.5) ? '0' : '1');
            }
            window.bb84_sessions[from] = { role:'receiver', measured, clientBases, serverBases, num };
            // send client_bases back to sender
            try{ socket.emit('bb84_relay', { room, to: from, bb84_type: 'client_bases', payload: { client_bases: clientBases } }); }catch(e){ console.error('emit client_bases failed', e); }
            // derive our session key now
            try{
              // compute raw bits where bases match
              let rawBitsArr = [];
              for(let i=0;i<serverBases.length;i++) if(serverBases[i] === clientBases[i]) rawBitsArr.push(measured[i]);
              const rawBits = rawBitsArr.join('');
              const hashBuf = await deriveSessionKeyFromRawBits(rawBits);
              window.bb84_sessions[from].session_hash = hashBuf;
              // if we are receiver, maybe trigger leader finalize on leader side later
            }catch(e){ console.error('derive session key (receiver) failed', e); }
          } else if(t === 'client_bases'){
            // sender receives client bases, derive session key and (if leader) encrypt RoomKey under it
            const clientBases = p.client_bases || '';
            const sess = window.bb84_sessions[from] || window.bb84_sessions[to];
            // sess should be stored under recipient key (to)
            const mySess = window.bb84_sessions[from] ? window.bb84_sessions[from] : null;
            // find session where role sender and matching bits
            let senderSess = null;
            // search for entries where role == 'sender' and bits length matches
            for(const k in window.bb84_sessions){
              const v = window.bb84_sessions[k];
              if(v && v.role === 'sender' && k === from){ senderSess = v; break; }
            }
            // fallback: try match on any sender entry
            if(!senderSess){
              for(const k in window.bb84_sessions){ const v=window.bb84_sessions[k]; if(v && v.role==='sender'){ senderSess=v; break; } }
            }
            if(!senderSess){ console.warn('client_bases: no sender session found'); return; }
            try{
              let rawBitsArr = [];
              for(let i=0;i<senderSess.bases.length;i++){
                if(senderSess.bases[i] === clientBases[i]) rawBitsArr.push(senderSess.bits[i]);
              }
              const rawBits = rawBitsArr.join('');
              const hashBuf = await deriveSessionKeyFromRawBits(rawBits);
              // store session hash for this peer
              // also store rawBits string and sift indices so we can do sample reveals
              const sift_indices = [];
              for(let i=0;i<senderSess.bases.length;i++) if(senderSess.bases[i] === clientBases[i]) sift_indices.push(i);
              window.bb84_sessions[ senderSess.to || from ] = Object.assign(window.bb84_sessions[ senderSess.to || from ] || {}, { session_hash: hashBuf, rawBits: rawBits, sift_indices });
              // perform a small sample reveal (sender -> receiver) to estimate QBER (only counts will be logged)
              try{
                const reveal_count = Math.min(10, sift_indices.length);
                if(reveal_count > 0){
                  // choose random sample indices from sift_indices
                  const sample = [];
                  const idxs = sift_indices.slice();
                  for(let k=0;k<reveal_count;k++){
                    const r = Math.floor(Math.random()*idxs.length);
                    const pos = idxs.splice(r,1)[0];
                    sample.push({ index: pos, bit: senderSess.bits[pos] });
                  }
                  try{ socket.emit('bb84_relay', { room, to: senderSess.to || from, bb84_type: 'reveal', payload: { samples: sample } }); }catch(e){ console.error('emit reveal failed', e); }
                }
              }catch(e){ console.error('reveal sample failed', e); }
              // emit non-sensitive BB84 metadata to server (matched count)
              try{ socket.emit('bb84_meta', { room, from: username, to: senderSess.to || from, matched_bits: (rawBits || '').length, original_bits: senderSess.num || (clientBases && clientBases.length) || 0 }); }catch(e){}
              // emit session-derived metadata (no key material)
              try{ socket.emit('bb84_session', { room, from: username, to: senderSess.to || from, key_length: (hashBuf && hashBuf.byteLength) || 32 }); }catch(e){}
              // trigger leader finalize check (leader will generate one RoomKey for all peers once all session_hashes ready)
              try{ maybeLeaderFinalize().catch(()=>{}); }catch(e){}
            }catch(e){ console.error('client_bases handling failed', e); }
          } else if(t === 'roomkey_enc'){
            // receiver decrypts roomkey using previously derived session_hash
            try{
              const combinedB64 = p.ciphertext || '';
              const arr = base64ToBytes(combinedB64);
              const iv = arr.slice(0,12);
              const ct = arr.slice(12).buffer;
              const sessObj = window.bb84_sessions[from] || {};
              const hashBuf = sessObj.session_hash;
              if(!hashBuf){ console.warn('no session hash for peer'); return; }
              const sessionKey = await window.crypto.subtle.importKey('raw', hashBuf, { name: 'AES-GCM' }, false, ['decrypt']);
              const roomRaw = await window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, sessionKey, ct);
              aesKey = await window.crypto.subtle.importKey('raw', roomRaw, { name: 'AES-GCM' }, false, ['encrypt','decrypt']);
              try{ document.getElementById('sessionStatus').innerText = 'Group key (BB84)'; document.getElementById('send').disabled = false; }catch(e){}
              window.dispatchEvent(new Event('groupKeyReady'));
              // notify server that this client successfully decrypted the room key
              try{ socket.emit('roomkey_decrypted', { room, user: username, from: from }); }catch(e){}
            }catch(e){ console.error('roomkey_enc handling failed', e); }
          }
        }catch(e){ console.error('bb84_message handler failed', e); }
      });

      socket.on('connect', () => {
        try{
          const expected = window.expectedUsers || null;
          const payload = { room, username };
          if(expected) payload.expected = expected;
          socket.emit('join', payload);
        }catch(e){ socket.emit('join', {room, username}); }
      });

      socket.on('join_failed', (d) => {
        try{
          const reason = (d && d.reason) ? d.reason : 'join failed';
          alert('Join failed: ' + reason);
          console.warn('join_failed', d);
        }catch(e){ console.error('join_failed handler error', e); }
      });

      // Handle incoming group_message relayed by server (ciphertext + iv separate)
      socket.on('group_message', async (d) => {
        try{
          if(!d) return;
          const from = d.from || 'unknown';
          const ciphertext = d.ciphertext || d.ct || '';
          const ivB64 = d.iv || '';
          if(!ciphertext) return;
          let combined = '';
          if (ivB64) {
            try{
              const ivBytes = base64ToBytes(ivB64);
              const ctBytes = base64ToBytes(ciphertext);
              const comb = new Uint8Array(ivBytes.length + ctBytes.length);
              comb.set(ivBytes, 0);
              comb.set(ctBytes, ivBytes.length);
              combined = bytesToBase64(comb);
            }catch(e){ console.error('combine iv+ct failed', e); combined = ivB64 + ciphertext; }
          } else {
            combined = ciphertext;
          }
          if (!combined || seenCiphertexts.has(combined)) return;
          // If we don't yet have group AES key, queue for later
          if (!aesKey && !(window.pairwiseKeys && window.pairwiseKeys['__group__'])) {
            incomingCipherQueue.push({ ciphertext: combined, from });
            renderEncryptedPlaceholder({ ciphertext: combined, from });
            return;
          }
          // try decrypt
          let packet = null;
          try{ packet = await decryptPacket(combined); }catch(e){
            const gk = (window.pairwiseKeys && window.pairwiseKeys['__group__']);
            if(gk) packet = await decryptWithKey(combined, gk);
            else throw e;
          }
          if(!packet || packet.kind !== 'chat') return;
          const to = packet.to || 'ALL';
          if (!(to === 'ALL' || to === username || packet.from === username)) return;
          seenCiphertexts.add(combined);
          // remove placeholder if present
          try{ const ph = placeholderMap[combined]; if(ph){ ph.remove(); delete placeholderMap[combined]; } }catch(e){}
          renderMessage(packet.from || from, to, packet.envelope || { type:'text', text: '' }, packet.from === username, packet.ts || (packet.envelope && packet.envelope.ts));
          // notify server that this client decrypted a message (no plaintext sent)
          try{ socket.emit('msg_decrypted', { room, user: username, sender: packet.from, text_length: (packet && packet.envelope && packet.envelope.text) ? packet.envelope.text.length : 0 }); }catch(e){}
        }catch(e){ console.error('group_message handler failed', e); }
      });

      socket.on('joined', () => { try{ processIncomingQueue(); processPersistedCipherHistory(); }catch(e){} });

      socket.on('user_list', (data) => {
        const sel = document.getElementById('recipient');
        const cur = sel.value;
        sel.innerHTML = '';
        const allOpt = document.createElement('option'); allOpt.value = 'ALL'; allOpt.text = 'All'; sel.appendChild(allOpt);
        const usersList = (data.users || []);
        // persist current users for BB84 coordination
        try{ window.currentUsers = usersList.slice(); }catch(e){}
        usersList.forEach(u => {
          const opt = document.createElement('option');
          opt.value = u;
          opt.text = u;
          if (u === username) opt.disabled = true;
          sel.appendChild(opt);
        });
        try{ sel.value = cur }catch(e){}
        document.getElementById('active').innerText = (data.users || []).length;
        // leader = first user in list. If leader, initiate BB84 prepares to peers.
        try{
          const leader = (usersList && usersList.length) ? usersList[0] : null;
          const prevLeader = window._currentLeader || null;
          window._currentLeader = leader;
          const becameLeader = (leader === username) && (prevLeader !== username);
          const lostLeadership = (prevLeader === username) && (leader !== username);
          window.isLeader = (leader === username);
          // If leadership changed and we're no longer leader, clear previous group key and sessions
          if(lostLeadership){
            try{
              aesKey = null;
              joinGroupKeyRawB64 = null;
              window.bb84_sessions = {};
              try{ document.getElementById('sessionStatus').innerText = 'No group key'; document.getElementById('send').disabled = true; }catch(e){}
            }catch(e){ console.error('clear group key on leadership loss failed', e); }
          }
          // If an expected user count is configured, wait until that many users have joined
          try{
            const expected = window.expectedUsers || null;
            const countMatches = expected ? (usersList.length === expected) : true;
            if(lostLeadership){ window.bb84_initiated = false; }
            if((window.isLeader || becameLeader) && countMatches && !window.bb84_initiated){
              // start BB84 sessions with each other user (non-blocking)
              try{
                usersList.forEach(u => {
                  if(u && u !== username && !(window.bb84_sessions && window.bb84_sessions[u])){
                    try{ sendBB84Prepare(u, 256); }catch(e){ console.error('start bb84 prepare failed', e); }
                  }
                });
                window.bb84_initiated = true;
                console.log('BB84 initiated by leader', username, 'for', usersList.length, 'users');
              }catch(e){ console.error('leader BB84 initiation failed', e); }
            } else if((window.isLeader || becameLeader) && expected && !countMatches){
              console.log('Waiting for expected users:', expected, 'current:', usersList.length);
            }
          }catch(e){ console.error('expected-check failed', e); }
        }catch(e){}
      });

      // Additional user_list handling removed (no quantum-specific auto-generation).

      // When a group key becomes available (created or received), snapshot it
      window.addEventListener('groupKeyReady', async ()=>{
        try{
          if(!joinGroupKeyRawB64 && window.encryption && window.encryption.createEncryptionModule && window.encryptionModule && window.encryptionModule.exportGroupKeyRawB64){
            try{ const b64 = await window.encryptionModule.exportGroupKeyRawB64(); if(b64) joinGroupKeyRawB64 = b64; }catch(e){}
          }
        }catch(e){}
        try{ await processIncomingQueue(); await processPersistedCipherHistory(); }catch(e){}
      });

      // mark whether we've received the initial room_logs from server
      window._roomLogsInitialized = window._roomLogsInitialized || false;
      // keep track of seen log ids so we append only new entries
      window._seenLogIds = window._seenLogIds || new Set();
      socket.on('room_logs', (data) => {
        const logs = (data && data.logs) ? data.logs : [];
        // sort chronologically
        const ordered = (logs || []).slice().sort((a,b) => (parseTs(a.created_at || '') || 0) - (parseTs(b.created_at || '') || 0));
        const container = document.getElementById('roomLogs');
        const encryptedPrefix = 'Encrypted message: ';
        const newPersisted = [];
        let anyNew = false;
        for(const l of ordered){
          const id = l && l.id ? l.id : null;
          if(id !== null){ if(window._seenLogIds.has(id)) continue; window._seenLogIds.add(id); }
          if(l && typeof l.message === 'string' && l.message.startsWith(encryptedPrefix)){
            newPersisted.push({ created_at: l.created_at || new Date().toISOString(), ciphertext: l.message.slice(encryptedPrefix.length) });
            anyNew = true;
            continue;
          }
          try{
            if(container){
              const ts = l.created_at || new Date().toISOString();
              container.innerText += `[${formatToIST(ts)}]\n${l.message || ''}\n\n`;
              container.scrollTop = container.scrollHeight;
              anyNew = true;
            }
          }catch(e){ console.error('append server log failed', e); }
        }
        try{ window._lastLogId = Math.max(window._lastLogId || 0, ...(ordered.map(x => x.id || 0))); }catch(_){ window._lastLogId = window._lastLogId || 0; }
        if (!window._roomLogsInitialized && (ordered.length > 0)) window._roomLogsInitialized = true;
        if(newPersisted.length) persistedCipherHistory = persistedCipherHistory.concat(newPersisted);
        if(anyNew){ window._lastLogReceivedAt = Date.now(); window._roomLogsBackoff = 0; }
        // parse BB84-related structured tags from ordered logs and update UI panel
        try{
          const stats = { original_bits: null, matched_bits: null, mismatched_bits: null, qber: null };
          for(const l of ordered){
            const msg = (l && l.message) ? String(l.message) : '';
            if(!msg) continue;
            // [BB84_INIT] from=... to=... length=NNN
            const mInit = msg.match(/\[BB84_INIT\][^0-9]*length=([0-9]+)/i);
            if(mInit && mInit[1]) stats.original_bits = parseInt(mInit[1], 10);
            // [BB84_SIFTING_COMPLETE] matched_bits=NNN [optional mismatches=NNN]
            const mSift = msg.match(/\[BB84_SIFTING_COMPLETE\][^0-9]*matched_bits=([0-9]+)/i);
            if(mSift && mSift[1]) stats.matched_bits = parseInt(mSift[1], 10);
            const mMismatch = msg.match(/mismatch(?:es|ed|ed_bits)?=([0-9]+)/i) || msg.match(/mismatched_bits=([0-9]+)/i);
            if(mMismatch && mMismatch[1]) stats.mismatched_bits = parseInt(mMismatch[1], 10);
            // Support logs that may include explicit QBER e.g. [BB84_QBER] qber=0.023
            const mQ = msg.match(/qber=([0-9.]+)/i);
            if(mQ && mQ[1]) stats.qber = parseFloat(mQ[1]);
          }
          // compute qber if possible
          if(stats.qber === null && stats.matched_bits && typeof stats.mismatched_bits === 'number'){
            stats.qber = stats.mismatched_bits / Math.max(1, stats.matched_bits);
          }
          // If mismatched_bits missing but qber and matched_bits present, infer mismatches
          if((stats.mismatched_bits === null || stats.mismatched_bits === undefined) && stats.qber !== null && stats.matched_bits){
            stats.mismatched_bits = Math.round(stats.qber * stats.matched_bits);
          }
          // Update BB84 panel via helper
          try{ setBB84Stats(stats); }catch(e){ console.error('update bb84 panel failed', e); }
        }catch(e){ console.error('bb84 parse failed', e); }

        processPersistedCipherHistory().catch(e => console.error('Persisted history replay failed', e));
      });

      // Push-friendly polling with exponential backoff when idle.
      window._roomLogsBackoff = window._roomLogsBackoff || 0;
      window._lastLogReceivedAt = window._lastLogReceivedAt || Date.now();
      function scheduleNextFetch() {
        const base = 5000; // base interval 5s
        const max = 30000; // max 30s
        const delay = Math.min(max, base * Math.pow(2, Math.max(0, window._roomLogsBackoff)));
        window._roomLogsFetchTimer = setTimeout(fetchRoomLogs, delay);
      }
      function fetchRoomLogs() {
        // don't poll until we've processed the initial server-sent room_logs
        if (!window._roomLogsInitialized) return scheduleNextFetch();
        try {
          socket.emit('fetch_room_logs', { room, since_id: window._lastLogId || 0 });
        } catch(e) { console.error('fetchRoomLogs emit failed', e); }
        // If we haven't received a new log in a while, increase backoff
        const idleMs = Date.now() - (window._lastLogReceivedAt || 0);
        if (idleMs > 5000) {
          window._roomLogsBackoff = Math.min(3, (window._roomLogsBackoff || 0) + 1);
        } else {
          window._roomLogsBackoff = 0;
        }
        scheduleNextFetch();
      }
      // start the fetch loop after a short delay
      setTimeout(fetchRoomLogs, 500);

      // Quantum distribution support removed; basic encryption helpers remain.

      socket.on('encrypted_message', async (d) => {
        const ciphertext = d.ciphertext || d.payload || '';
        if (!ciphertext || seenCiphertexts.has(ciphertext)) return;
        // If we don't yet have the room AES key, queue ciphertexts for later processing
        if (!aesKey && !(window.pairwiseKeys && window.pairwiseKeys['__group__'])) {
          incomingCipherQueue.push(d);
          renderEncryptedPlaceholder(d);
          console.log('Queued incoming ciphertext until key is ready');
          return;
        }
        try{
          const packet = await decryptPacket(ciphertext);
          if (packet.kind !== 'chat') return;
          const to = packet.to || 'ALL';
          const from = packet.from || 'unknown';
          if (!(to === 'ALL' || to === username || from === username)) return;
          const envelope = packet.envelope || { type: 'text', text: '' };
          seenCiphertexts.add(ciphertext);
          renderMessage(from, to, envelope, from === username, packet.ts || (envelope && envelope.ts));
        }catch(e){ console.error('decrypt failed', e); }
      });

      function renderEncryptedPlaceholder(d){
        try{
          const ciphertext = d.ciphertext || d.payload || '';
          if(!ciphertext || placeholderMap[ciphertext]) return;
          const from = d.from || 'unknown';
          const ts = new Date().toISOString();
          const logEl = document.getElementById('log');
          const item = document.createElement('div');
          item.className = 'mb-2 rounded-lg border px-3 py-2 border-[#d2dce7] bg-white';
          const meta = document.createElement('div');
          meta.className = 'mb-1 text-xs text-[#5f6e7f]';
          meta.textContent = `${from} -> ALL · ${formatToIST(ts)}`;
          item.appendChild(meta);
          const body = document.createElement('div');
          body.className = 'whitespace-pre-wrap break-words text-sm text-[#5f6e7f]';
          body.textContent = '🔒 Encrypted message (waiting for key)';
          item.appendChild(body);
          logEl.appendChild(item);
          logEl.scrollTop = logEl.scrollHeight;
          placeholderMap[ciphertext] = item;
        }catch(e){ console.error('renderEncryptedPlaceholder failed', e); }
      }

      document.getElementById('send').onclick = async () => {
        const messageEl = document.getElementById('message');
        const textRaw = messageEl.value.trim();
        let text = textRaw;
        // Prefer group messaging if encryption module has a group key
        const hasEncGroup = (window.encryptionModule && window.encryptionModule.hasGroupKey && window.encryptionModule.hasGroupKey());
        if (hasEncGroup && !pendingAttachment) {
          if (!text) return;
          try{
            // If we captured a join-time key, use that to encrypt (so messages use the key present at join)
            if (joinGroupKeyRawB64 && subtleCrypto) {
              try{
                // import join-time raw key
                const raw = base64ToBytes(joinGroupKeyRawB64);
                const key = await subtleCrypto.importKey('raw', raw, { name: 'AES-GCM' }, false, ['encrypt']);
                const iv = window.crypto.getRandomValues(new Uint8Array(12));
                const pt = new TextEncoder().encode(text);
                const ctBuf = await subtleCrypto.encrypt({ name: 'AES-GCM', iv }, key, pt);
                const ctB64 = bytesToBase64(new Uint8Array(ctBuf));
                const ivB64 = bytesToBase64(iv);
                // store combined iv+ct for history/deferred decrypt path
                const combined = new Uint8Array(iv.byteLength + ctBuf.byteLength);
                combined.set(iv, 0); combined.set(new Uint8Array(ctBuf), iv.byteLength);
                const combinedB64 = bytesToBase64(combined);
                // render locally
                seenCiphertexts.add(combinedB64);
                renderMessage(username, 'ALL', { type:'text', text }, true, new Date().toISOString());
                // persist ciphertext for room history (server will store under room)
                try{ socket.emit('store_encrypted', { room, ciphertext: combinedB64 }); }catch(e){ console.error('store_encrypted emit failed', e); }
                // relay group message to peers (send separate iv & ct so receivers using current group key can decrypt)
                try{ socket.emit('relay', { type: 'group_message', room, from: username, ciphertext: ctB64, iv: ivB64 }); }catch(e){ console.error('relay group_message failed', e); }
                messageEl.value = '';
                return;
              }catch(err){ console.error('join-time encrypt failed', err); }
            }
            // Fallback to module-managed send (uses current live group key)
            try{
              const res = await window.encryptionModule.sendGroupMessage(text);
              if(res && res.ctB64 && res.ivB64){
                const iv = base64ToBytes(res.ivB64);
                const ct = base64ToBytes(res.ctB64);
                const combined = new Uint8Array(iv.byteLength + ct.byteLength);
                combined.set(iv, 0); combined.set(ct, iv.byteLength);
                const combinedB64 = bytesToBase64(combined);
                seenCiphertexts.add(combinedB64);
                try{ socket.emit('store_encrypted', { room, ciphertext: combinedB64 }); }catch(e){ console.error('store_encrypted emit failed', e); }
              }
              messageEl.value = '';
              return;
            }catch(e){ console.error('encryptionModule.sendGroupMessage failed', e); }
          }catch(e){ console.error('encryptionModule.sendGroupMessage failed', e); }
        }

        // prepare recipient/envelope early so we can fallback to plaintext if needed
        if (pendingAttachment && textRaw === pendingAttachment.marker) text = '';
        if (!text && !pendingAttachment) return;
        const to = document.getElementById('recipient').value || 'ALL';
        let envelope;
        if (pendingAttachment) {
          const rawBytes = new Uint8Array(await pendingAttachment.file.arrayBuffer());
          envelope = {
            type: 'file',
            name: pendingAttachment.file.name,
            mime: pendingAttachment.file.type || 'application/octet-stream',
            size: pendingAttachment.file.size,
            data_b64: bytesToBase64(rawBytes),
            text,
            ts: new Date().toISOString()
          };
        } else {
          envelope = { type: 'text', text, ts: new Date().toISOString() };
        }

        // If no AES/group key is available, fallback to a classical plaintext message
        if (!aesKey && !(window.encryptionModule && window.encryptionModule.hasGroupKey && window.encryptionModule.hasGroupKey())) {
          try{
            // render locally for sender
            renderMessage(username, to, envelope, true, envelope.ts);
          }catch(e){}
          try{
            const plainPayload = (envelope.type === 'text') ? envelope.text : JSON.stringify(envelope);
            socket.emit('plain_message', { room, from: username, to, message: plainPayload, ts: envelope.ts });
          }catch(e){ console.error('plain_message emit failed', e); }
          messageEl.value = '';
          pendingAttachment = null;
          return;
        }

        // Fallback to existing encrypted_message path (requires aesKey)
        if (!aesKey) {
          ensureRoomKey();
          return;
        }
        const packet = {
          v: 1,
          kind: 'chat',
          from: username,
          to,
          ts: new Date().toISOString(),
          envelope
        };
        const ciphertext = await encryptPacket(packet);
        // Store encrypted ciphertext in server DB (server will NOT forward to participants)
        try{
          // render locally for sender
          seenCiphertexts.add(ciphertext);
          renderMessage(username, to, envelope, true, packet.ts);
        }catch(e){ console.error('local render failed', e); }
        try{
          console.log('[client] emitting store_encrypted', { room, len: ciphertext.length });
          socket.emit('store_encrypted', { room, ciphertext });
        }catch(e){ console.error('store_encrypted emit failed', e); }
        messageEl.value = '';
        pendingAttachment = null;
      };

      // Manual group-key UI removed; key distribution handled automatically or elsewhere.

      document.getElementById('message').addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && !e.shiftKey) {
          const sendBtn = document.getElementById('send');
          if (!sendBtn.disabled) {
            e.preventDefault();
            sendBtn.click();
          }
        }
      });

      document.getElementById('attachBtn').onclick = () => {
        if (!aesKey) {
          ensureRoomKey();
          return;
        }
        document.getElementById('fileInput').click();
      };

      document.getElementById('fileInput').addEventListener('change', async (e) => {
        const file = e.target.files && e.target.files[0];
        e.target.value = '';
        if (!file) return;
        if (!aesKey) {
          ensureRoomKey();
          return;
        }
        if (file.size > MAX_FILE_BYTES) {
          console.log(`Attachment blocked: ${file.name} is larger than ${formatBytes(MAX_FILE_BYTES)}`);
          return;
        }
        const marker = `[Attached] ${file.name}`;
        pendingAttachment = { file, marker };
        document.getElementById('message').value = marker;
      });

      // AI Summary UI removed; no refresh handler

      const fullscreenBtn = document.getElementById('fullscreenToggle');
      fullscreenBtn.onclick = () => {
        applyChatFullscreen(!document.body.classList.contains('chat-fullscreen'));
      };

      document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape' && document.body.classList.contains('chat-fullscreen')) {
          applyChatFullscreen(false);
        }
      });

      // If the browser fullscreen API is used, mirror that into our CSS class so the header hides.
      document.addEventListener('fullscreenchange', () => {
        const isFs = !!document.fullscreenElement;
        document.body.classList.toggle('in-fullscreen', isFs);
        try { localStorage.setItem(FULLSCREEN_PREF_KEY, isFs ? '1' : '0'); } catch (_) {}
      });

      function legacyCopyText(text) {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.setAttribute('readonly', '');
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.focus();
        ta.select();
        let ok = false;
        try {
          ok = document.execCommand('copy');
        } catch (_) {
          ok = false;
        }
        document.body.removeChild(ta);
        return ok;
      }

      async function handleCopyRoom() {
        const state = document.getElementById('copyState');
        let copied = false;
        try {
          if (navigator.clipboard && window.isSecureContext) {
            await navigator.clipboard.writeText(room);
            copied = true;
          } else {
            copied = legacyCopyText(room);
          }
        } catch (_) {
          copied = legacyCopyText(room);
        }

        if (copied) {
          state.innerText = 'Copied';
          setTimeout(() => { state.innerText = ''; }, 1500);
        } else {
          state.innerText = 'Copy failed';
        }
      }
      const copyIcon = document.getElementById('copyRoomIcon');
      copyIcon.onclick = handleCopyRoom;
      copyIcon.onkeydown = (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          handleCopyRoom();
        }
      };

      // Initialize custom select after user list updates may run
      function initCustomSelectIfPresent() {
        try {
          const sel = document.getElementById('recipient');
          const display = document.getElementById('recipientDisplay');
          const list = document.getElementById('recipientList');
          if (!sel || !display || !list) return;

          function rebuild() {
            list.innerHTML = '';
            for (let i = 0; i < sel.options.length; i++) {
              const opt = sel.options[i];
              const li = document.createElement('li');
              li.className = 'custom-select-item';
              li.setAttribute('role', 'option');
              li.setAttribute('data-value', opt.value);
              li.textContent = opt.textContent;
              if (sel.value === opt.value) li.setAttribute('aria-selected', 'true');
              li.addEventListener('click', () => {
                sel.value = opt.value;
                display.firstChild.nodeValue = opt.textContent + ' ';
                sel.dispatchEvent(new Event('change', { bubbles: true }));
                close();
              });
              list.appendChild(li);
            }
          }

          function open() { list.classList.add('open'); display.setAttribute('aria-expanded', 'true'); }
          function close() { list.classList.remove('open'); display.setAttribute('aria-expanded', 'false'); }

          display.addEventListener('click', (e) => { e.stopPropagation(); if (list.classList.contains('open')) close(); else open(); });
          document.addEventListener('click', (e) => { if (!list.contains(e.target) && !display.contains(e.target)) close(); });

          // Keep display text in sync
          display.firstChild && (display.firstChild.nodeValue = (sel.selectedOptions[0] || {}).textContent || sel.value + ' ');
          // rebuild anytime user_list updates select options
          const observer = new MutationObserver(rebuild);
          observer.observe(sel, { childList: true, subtree: true });
          rebuild();
        } catch (e) { console.error('initCustomSelectIfPresent failed', e); }
      }

      // run once to initialize; user_list updates will mutate the select and observer will rebuild
      initCustomSelectIfPresent();

      // AI Summary removed
      try { applyChatFullscreen(localStorage.getItem(FULLSCREEN_PREF_KEY) === '1'); } catch (_) {}
      try{ resetBB84Stats(); }catch(_){}
    