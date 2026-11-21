'use strict';
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const AGENT_KEY = process.env.AGENT_KEY || ''; // clé du téléphone du propriétaire (partageur « owner »)
if (ADMIN_PASSWORD.length < 12 || AGENT_KEY.length < 24) {
  console.error('ADMIN_PASSWORD (12 caractères min.) et AGENT_KEY (24 caractères min.) sont obligatoires.');
  process.exit(1);
}
// Les clés des autres partageurs se déduisent de ce secret : le serveur n’a rien à mémoriser à leur sujet.
const SECRET = process.env.SECRET || crypto.createHash('sha256').update(ADMIN_PASSWORD + '|' + AGENT_KEY).digest('hex');
const OWNER_NAME = process.env.OWNER_NAME || 'Propriétaire';
const MAX_SHARERS = 30;

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const rand = (n) => crypto.randomBytes(n).toString('hex');
const hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const clean = (s, n) => String(s || '').replace(/[\u0000-\u001f\u007f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, n);
const cleanName = (s, n) => clean(s, n).replace(/['"`$\\]/g, '');

// Tout reste en mémoire sauf la liste des invités de chaque partageur : elle est conservée sur SON téléphone
// (empreintes des jetons, jamais les jetons) et rechargée quand il se reconnecte après un redémarrage du serveur.
const sessions = new Map(); // sid -> expiration (administration)
const requests = new Map(); // numéro à 6 chiffres -> { sid, name, secret, status, token, createdAt }
const guests = new Map();   // empreinte du jeton -> { sid, gid, name, since, tunnels }
const sharers = new Map();  // id -> { id, name, ws, paused, loaded }
const waiting = new Map();  // id de tunnel -> { sid, ws, timer, stream | onPaired }
const banned = new Set();   // partageurs retirés par l’administrateur (jusqu’au prochain redémarrage)
let failures = 0;
let lockedUntil = 0;
const regTimes = [];

const keyFor = (id) => `${id}.${crypto.createHmac('sha256', SECRET).update('sharer:' + id).digest('hex')}`;
function identify(key) {
  if (typeof key !== 'string' || key.length > 200) return null;
  if (same(key, AGENT_KEY)) return 'owner';
  const m = /^([a-f0-9]{12})\.([a-f0-9]{64})$/.exec(key);
  if (!m || banned.has(m[1])) return null;
  return same(key, keyFor(m[1])) ? m[1] : null;
}
const online = (s) => Boolean(s && s.ws && s.ws.readyState === WebSocket.OPEN);
const nameOf = (sid) => (sharers.get(sid) || {}).name || '—';

const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'";

function send(res, code, body, type = 'application/json') {
  res.writeHead(code, {
    'Content-Type': type + '; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
    'Strict-Transport-Security': 'max-age=31536000',
    'Content-Security-Policy': CSP,
  });
  res.end(type === 'application/json' ? JSON.stringify(body) : body);
}

function readJson(req) {
  return new Promise((resolve) => {
    if (!(req.headers['content-type'] || '').startsWith('application/json')) return resolve(null);
    let data = '';
    req.on('data', (c) => {
      data += c;
      if (data.length > 2000) { req.destroy(); resolve(null); }
    });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch { resolve(null); } });
    req.on('error', () => resolve(null));
  });
}

function isAdmin(req) {
  const m = /(?:^|; )sid=([a-f0-9]{48})/.exec(req.headers.cookie || '');
  const exp = m && sessions.get(m[1]);
  return Boolean(exp && exp > Date.now());
}
// Qui fait la demande : l’administrateur (cookie) ou un partageur (sa clé dans le corps de la requête)
function actor(req, body) {
  if (isAdmin(req)) return { admin: true };
  const sid = identify(body && body.key);
  return sid ? { sid } : null;
}

function publicHost(req) {
  const h = String(process.env.PUBLIC_HOST || req.headers['x-forwarded-host'] || req.headers.host || '').split(',')[0].trim();
  return /^[a-z0-9.-]+(:\d+)?$/i.test(h) ? h : 'localhost';
}
const originOf = (host) => (/^(localhost|127\.|\[?::1)/.test(host) ? 'http://' : 'https://') + host;

function termuxCommand(origin, key, name) {
  return [
    'pkg update -y',
    'pkg upgrade -y -o Dpkg::Options::=--force-confnew', // mise à jour complète : installer nodejs seul peut le casser (bibliothèque libicu manquante)
    'pkg install -y nodejs curl',
    'mkdir -p ~/partage',
    'cd ~/partage',
    `curl -fsSL ${origin}/agent.js -o agent.js`,
    'npm install ws@8',
    `printf '%s\\n' 'export SERVER_URL=${origin}' 'export AGENT_KEY=${key}' 'export SHARER_NAME="${name}"' 'termux-wake-lock' 'cd ~/partage && node agent.js' > start.sh`,
    'chmod 600 start.sh',
    'bash start.sh',
  ].join(' && ');
}

function snapshot(sid) {
  return [...guests.entries()].filter(([, g]) => g.sid === sid).map(([h, g]) => ({ h, gid: g.gid, name: g.name, since: g.since }));
}
function persist(sid) {
  const s = sharers.get(sid);
  if (!online(s)) return false;
  try { s.ws.send(JSON.stringify({ t: 'save', guests: snapshot(sid) })); return true; } catch { return false; }
}
function loadGuests(sid, list) {
  if (!Array.isArray(list)) return;
  for (const g of list.slice(0, 200)) {
    if (g && /^[a-f0-9]{64}$/.test(g.h) && /^[a-f0-9]{8}$/.test(g.gid) && typeof g.name === 'string' && !guests.has(g.h)) {
      guests.set(g.h, { sid, gid: g.gid, name: cleanName(g.name, 40), since: Number(g.since) || Date.now(), tunnels: new Set() });
    }
  }
}
function dropGuest(h) {
  const g = guests.get(h);
  if (!g) return;
  guests.delete(h);
  for (const ws of g.tunnels) ws.terminate();
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'GET') {
    if (p === '/health') return send(res, 200, 'ok', 'text/plain');
    if (p === '/') return send(res, 200, HOME_HTML, 'text/html');
    if (p === '/partager') return send(res, 200, SHARE_HTML, 'text/html');
    if (p === '/connecter' || p === '/demande') return send(res, 200, CONNECT_HTML, 'text/html');
    if (p === '/mon-partage') return send(res, 200, PANEL_HTML, 'text/html');
    if (p === '/admin') return send(res, 200, ADMIN_HTML, 'text/html');

    if (p === '/agent.js') { // le programme à installer sur le téléphone du partageur
      let code;
      try { code = fs.readFileSync(path.join(__dirname, 'agent.js')); }
      catch { return send(res, 404, 'agent.js est introuvable sur le serveur.', 'text/plain'); }
      res.writeHead(200, { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'no-store' });
      return res.end(code);
    }

    const sub = /^\/sub\/([0-9a-f-]{36})$/.exec(p); // abonnement lu par l’application VPN (bouton « Ouvrir dans l’application »)
    if (sub) {
      if (!guests.has(hex(sub[1]))) return send(res, 404, 'inconnu', 'text/plain');
      const h = publicHost(req);
      const link = `vless://${sub[1]}@${h}:443?encryption=none&security=tls&sni=${h}&type=ws&host=${h}&path=%2Fvless#relais-maison`;
      return send(res, 200, Buffer.from(link).toString('base64'), 'text/plain');
    }

    if (p === '/api/sharers') { // liste publique des connexions disponibles
      return send(res, 200, {
        sharers: [...sharers.values()].filter((s) => online(s) && !s.paused).map((s) => ({ id: s.id, name: s.name })),
      });
    }
    if (p === '/api/status') {
      const r = requests.get(url.searchParams.get('id') || '');
      if (!r || !same(r.secret, url.searchParams.get('secret') || '')) return send(res, 404, { status: 'expired' });
      if (r.status === 'approved' && r.token) {
        const token = r.token;
        r.token = null; // le jeton n’est remis qu’une seule fois
        return send(res, 200, { status: 'approved', token });
      }
      return send(res, 200, { status: r.status === 'approved' ? 'delivered' : r.status });
    }
    if (p === '/api/admin/state') {
      if (!isAdmin(req)) return send(res, 401, { error: 'non autorisé' });
      return send(res, 200, {
        sharers: [...sharers.values()].map((s) => ({
          id: s.id, name: s.name, online: online(s), paused: s.paused,
          guests: [...guests.values()].filter((g) => g.sid === s.id).length,
        })),
        pending: [...requests.entries()].filter(([, r]) => r.status === 'pending').map(([id, r]) => ({ id, name: r.name, sharer: nameOf(r.sid) })),
        guests: [...guests.values()].map((g) => ({ gid: g.gid, name: g.name, tunnels: g.tunnels.size, sharer: nameOf(g.sid) })),
      });
    }
    return send(res, 404, { error: 'introuvable' });
  }

  if (req.method !== 'POST') return send(res, 405, { error: 'méthode refusée' });
  const body = await readJson(req);
  if (!body) return send(res, 400, { error: 'requête invalide' });

  // ----- Public -----
  if (p === '/api/sharer/register') {
    const now = Date.now();
    while (regTimes.length && now - regTimes[0] > 10 * 60e3) regTimes.shift();
    if (regTimes.length >= 20) return send(res, 429, { error: 'Trop de créations récentes. Réessayez dans quelques minutes.' });
    const name = cleanName(body.name, 30);
    if (!name) return send(res, 400, { error: 'Choisissez un nom.' });
    regTimes.push(now);
    const id = rand(6);
    const key = keyFor(id);
    return send(res, 200, { id, key, name, command: termuxCommand(originOf(publicHost(req)), key, name) });
  }

  if (p === '/api/sharer/status') {
    const sid = identify(body.key);
    if (!sid) return send(res, 401, { error: 'clé invalide' });
    const s = sharers.get(sid);
    return send(res, 200, { online: online(s), name: s ? s.name : null });
  }

  if (p === '/api/request') {
    const s = sharers.get(String(body.sharerId));
    if (!online(s) || s.paused) return send(res, 409, { error: 'Cette connexion n’est plus disponible.' });
    const name = cleanName(body.name, 40);
    if (!name) return send(res, 400, { error: 'nom requis' });
    const open = [...requests.values()].filter((r) => r.status === 'pending');
    if (open.length >= 100 || open.filter((r) => r.sid === s.id).length >= 10) return send(res, 429, { error: 'trop de demandes' });
    let id;
    do { id = String(crypto.randomInt(100000, 1000000)); } while (requests.has(id));
    const secret = rand(16);
    requests.set(id, { sid: s.id, name, secret, status: 'pending', token: null, createdAt: Date.now() });
    return send(res, 200, { id, secret, sharer: s.name });
  }

  if (p === '/api/login') {
    if (Date.now() < lockedUntil) return send(res, 429, { error: 'Trop d’essais. Réessayez dans quelques minutes.' });
    if (typeof body.password === 'string' && same(body.password, ADMIN_PASSWORD)) {
      failures = 0;
      const sid = rand(24);
      sessions.set(sid, Date.now() + 12 * 3600e3);
      res.setHeader('Set-Cookie', `sid=${sid}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=43200`);
      return send(res, 200, { ok: true });
    }
    if (++failures >= 8) { lockedUntil = Date.now() + 10 * 60e3; failures = 0; }
    return send(res, 401, { error: 'Mot de passe incorrect.' });
  }

  // ----- Partageur (clé) ou administrateur (cookie) -----
  const who = actor(req, body);
  if (!who) return send(res, 401, { error: 'non autorisé' });

  if (p === '/api/logout') {
    const m = /(?:^|; )sid=([a-f0-9]{48})/.exec(req.headers.cookie || '');
    if (m) sessions.delete(m[1]);
    return send(res, 200, { ok: true });
  }

  if (p === '/api/mine/state') {
    if (!who.sid) return send(res, 400, { error: 'clé de partageur requise' });
    const s = sharers.get(who.sid);
    return send(res, 200, {
      known: Boolean(s), online: online(s), paused: Boolean(s && s.paused), name: s ? s.name : null,
      pending: [...requests.entries()].filter(([, r]) => r.status === 'pending' && r.sid === who.sid).map(([id, r]) => ({ id, name: r.name })),
      guests: [...guests.values()].filter((g) => g.sid === who.sid).map((g) => ({ gid: g.gid, name: g.name, tunnels: g.tunnels.size })),
    });
  }

  if (p === '/api/mine/pause') {
    const s = who.sid && sharers.get(who.sid);
    if (!s) return send(res, 404, { error: 'partageur inconnu' });
    s.paused = Boolean(body.paused);
    return send(res, 200, { ok: true, paused: s.paused });
  }

  if (p === '/api/decision') {
    const r = requests.get(String(body.id));
    if (!r || r.status !== 'pending' || (!who.admin && r.sid !== who.sid)) return send(res, 404, { error: 'demande introuvable' });
    if (body.action === 'approve') {
      const s = sharers.get(r.sid);
      if (!online(s)) return send(res, 503, { error: 'Le téléphone du partageur est hors ligne : réessayez dans un instant.' });
      if ([...guests.values()].filter((g) => g.sid === r.sid).length >= 100) return send(res, 429, { error: 'Trop d’invités pour ce partageur.' });
      const token = crypto.randomUUID();
      guests.set(hex(token), { sid: r.sid, gid: rand(4), name: r.name, since: Date.now(), tunnels: new Set() });
      persist(r.sid);
      r.status = 'approved';
      r.token = token;
    } else {
      r.status = 'rejected';
    }
    return send(res, 200, { ok: true });
  }

  if (p === '/api/revoke') { // « Couper » : un invité (gid) ou tous les invités du partageur (all)
    const targets = [...guests.entries()].filter(([, g]) => (who.admin || g.sid === who.sid) && (body.all ? (!body.sid || g.sid === body.sid) : g.gid === body.gid));
    const sids = new Set(targets.map(([, g]) => g.sid));
    for (const sid of sids) if (!online(sharers.get(sid))) return send(res, 503, { error: 'Le téléphone du partageur est hors ligne : la coupure doit y être enregistrée. Réessayez dans un instant.' });
    for (const [h] of targets) dropGuest(h);
    for (const sid of sids) persist(sid);
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/kick') { // retire un partageur (administrateur seulement)
    if (!who.admin) return send(res, 401, { error: 'non autorisé' });
    const sid = String(body.sid);
    if (sid === 'owner' || !sharers.has(sid)) return send(res, 404, { error: 'partageur introuvable' });
    banned.add(sid);
    for (const [h, g] of guests) if (g.sid === sid) dropGuest(h);
    const s = sharers.get(sid);
    if (s.ws) s.ws.terminate();
    sharers.delete(sid);
    return send(res, 200, { ok: true });
  }

  send(res, 404, { error: 'introuvable' });
});

// ---------- Tunnels (WebSocket) ----------
const wss = new WebSocket.Server({ noServer: true, maxPayload: 1 << 20 });
wss.on('connection', (ws) => {
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
});

// En mode noServer, 'connection' n’est pas émis tout seul : on l’émet ici pour activer le suivi de vie des connexions
const upgrade = (req, socket, head, cb) =>
  wss.handleUpgrade(req, socket, head, (ws) => { wss.emit('connection', ws, req); cb(ws); });

// ---------- Compatibilité VLESS (applications VPN existantes) ----------
const DOH_URL = process.env.DOH_URL || 'https://cloudflare-dns.com/dns-query';

function parseVless(buf) {
  try {
    if (buf.length < 24 || buf[0] !== 0) return null;
    const h = buf.subarray(1, 17).toString('hex');
    const uuid = `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
    let o = 18 + buf[17];
    const cmd = buf[o++];
    const port = buf.readUInt16BE(o); o += 2;
    const type = buf[o++];
    let host;
    if (type === 1) { host = [...buf.subarray(o, o + 4)].join('.'); o += 4; }
    else if (type === 2) { const n = buf[o++]; host = buf.subarray(o, o + n).toString(); o += n; }
    else return null;
    return { uuid, cmd, port, host, rest: buf.subarray(o) };
  } catch { return null; }
}

// Envoie des données en ralentissant l’émetteur si le destinataire est saturé
function sendFlow(to, data, from) {
  if (to.readyState !== WebSocket.OPEN) return;
  to.send(data, { binary: true });
  if (to.bufferedAmount > (1 << 21) && !from.flowPaused) {
    from.flowPaused = true;
    from.pause();
    const t = setInterval(() => {
      if (to.readyState !== WebSocket.OPEN || to.bufferedAmount < (1 << 18)) { clearInterval(t); from.flowPaused = false; from.resume(); }
    }, 50);
  }
}

function handleVless(ws) {
  let phase = 'init';
  let guest = null;
  let peer = null;
  let wid = null;
  let udpBuf = Buffer.alloc(0);
  const pending = [];
  const done = () => { ws.terminate(); if (peer) peer.terminate(); };

  ws.on('error', () => {});
  ws.on('close', () => {
    if (guest) guest.tunnels.delete(ws);
    if (wid) { const w = waiting.get(wid); if (w) clearTimeout(w.timer); waiting.delete(wid); }
    if (peer) peer.terminate();
  });

  // Les requêtes DNS (UDP 53) sont envoyées en DNS-sur-HTTPS depuis le serveur
  async function dnsFrames(chunk) {
    udpBuf = Buffer.concat([udpBuf, chunk]);
    while (udpBuf.length >= 2) {
      const n = udpBuf.readUInt16BE(0);
      if (udpBuf.length < 2 + n) break;
      const q = udpBuf.subarray(2, 2 + n);
      udpBuf = udpBuf.subarray(2 + n);
      try {
        const r = await fetch(DOH_URL, { method: 'POST', headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' }, body: q });
        const a = Buffer.from(await r.arrayBuffer());
        const f = Buffer.alloc(2 + a.length);
        f.writeUInt16BE(a.length, 0);
        a.copy(f, 2);
        if (ws.readyState === WebSocket.OPEN) ws.send(f, { binary: true });
      } catch { /* requête perdue : l’application réessaiera */ }
    }
  }

  ws.on('message', (data) => {
    const buf = Buffer.from(data);
    if (phase === 'piped') return sendFlow(peer, buf, ws);
    if (phase === 'connecting') { pending.push(buf); return; }
    if (phase === 'dns') return dnsFrames(buf);

    const h = parseVless(buf);
    guest = h && guests.get(hex(h.uuid)); // les invités sont indexés par l’empreinte de leur jeton
    if (!guest || guest.tunnels.size >= 300) return done();
    guest.tunnels.add(ws);
    const s = sharers.get(guest.sid);

    if (h.cmd === 2 && h.port === 53) {
      phase = 'dns';
      ws.send(Buffer.from([0, 0]), { binary: true });
      return dnsFrames(h.rest);
    }
    if (h.cmd !== 1 || !online(s) || !/^[a-zA-Z0-9.-]{1,253}$/.test(h.host)) return done();

    phase = 'connecting';
    if (h.rest.length) pending.push(h.rest);
    wid = rand(8);
    const timer = setTimeout(() => { waiting.delete(wid); done(); }, 10000);
    waiting.set(wid, {
      sid: guest.sid,
      ws,
      timer,
      onPaired: (a) => {
        peer = a;
        phase = 'piped';
        ws.send(Buffer.from([0, 0]), { binary: true });
        for (const c of pending.splice(0)) a.send(c, { binary: true });
        a.on('message', (d) => sendFlow(ws, Buffer.from(d), a));
        a.on('close', done);
        a.on('error', () => {});
      },
    });
    try { s.ws.send(JSON.stringify({ t: 'open', id: wid, host: h.host, port: h.port })); } catch { done(); }
  });
}

server.on('upgrade', (req, socket, head) => {
  const refuse = (status) => { socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  const url = new URL(req.url, 'http://x');
  const h = req.headers;
  const agentSid = url.pathname === '/agent' || url.pathname === '/agent-stream' ? identify(h['x-agent-key']) : null;

  // Le téléphone d’un partageur garde cette connexion ouverte et reçoit les demandes d’ouverture
  if (url.pathname === '/agent') {
    if (!agentSid) return refuse('401 Unauthorized');
    if (!sharers.has(agentSid) && sharers.size >= MAX_SHARERS) return refuse('503 Service Unavailable');
    return upgrade(req, socket, head, (ws) => {
      let s = sharers.get(agentSid);
      if (!s) {
        s = { id: agentSid, name: agentSid === 'owner' ? OWNER_NAME : 'Partageur', ws: null, paused: false, loaded: false };
        sharers.set(agentSid, s);
      }
      if (s.ws) s.ws.terminate();
      s.ws = ws;
      ws.on('message', (d) => {
        try {
          const m = JSON.parse(d);
          if (m.t === 'hello') {
            const nm = cleanName(m.name, 30);
            if (nm) s.name = nm;
            if (!s.loaded) { loadGuests(agentSid, m.guests); s.loaded = true; }
            persist(agentSid);
            ws.send(JSON.stringify({ t: 'welcome', name: s.name }));
            return;
          }
          const w = waiting.get(m.id);
          if (m.t === 'fail' && w && w.sid === agentSid) { waiting.delete(m.id); clearTimeout(w.timer); w.ws.terminate(); }
        } catch { /* ignoré */ }
      });
      ws.on('close', () => { if (s.ws === ws) s.ws = null; });
    });
  }

  // Le téléphone du partageur ouvre un flux par connexion demandée
  if (url.pathname === '/agent-stream') {
    const id = url.searchParams.get('id') || '';
    const w = waiting.get(id);
    if (!agentSid || !w || w.sid !== agentSid) return refuse('404 Not Found');
    waiting.delete(id);
    clearTimeout(w.timer);
    return upgrade(req, socket, head, (ws) => {
      if (w.onPaired) return w.onPaired(ws);
      const b = WebSocket.createWebSocketStream(ws);
      w.stream.pipe(b);
      b.pipe(w.stream);
      const stop = () => { ws.terminate(); w.ws.terminate(); };
      b.on('error', stop);
      w.stream.on('error', stop);
      ws.on('close', stop);
      w.ws.on('close', stop);
    });
  }

  // Un invité autorisé demande une connexion vers host:port
  if (url.pathname === '/tunnel') {
    const g = typeof h['x-token'] === 'string' ? guests.get(hex(h['x-token'])) : undefined;
    const s = g && sharers.get(g.sid);
    const host = url.searchParams.get('host') || '';
    const port = Number(url.searchParams.get('port'));
    if (!g) return refuse('401 Unauthorized');
    if (!online(s)) return refuse('503 Service Unavailable');
    if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535 || g.tunnels.size >= 300) {
      return refuse('400 Bad Request');
    }
    return upgrade(req, socket, head, (ws) => {
      if (!online(s)) return ws.terminate();
      const stream = WebSocket.createWebSocketStream(ws); // met en mémoire les données reçues avant l’appairage
      const id = rand(8);
      const timer = setTimeout(() => { waiting.delete(id); ws.terminate(); }, 10000);
      waiting.set(id, { sid: g.sid, stream, ws, timer });
      g.tunnels.add(ws);
      ws.on('close', () => { g.tunnels.delete(ws); clearTimeout(timer); waiting.delete(id); });
      stream.on('error', () => ws.terminate());
      try { s.ws.send(JSON.stringify({ t: 'open', id, host, port })); } catch { ws.terminate(); }
    });
  }

  // Applications VPN existantes (v2rayNG, v2rayN…) : protocole VLESS sur WebSocket
  if (url.pathname === '/vless') return upgrade(req, socket, head, (ws) => handleVless(ws));

  refuse('404 Not Found');
});

setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 30e3).unref();

setInterval(() => {
  const now = Date.now();
  for (const [id, r] of requests) if (now - r.createdAt > 15 * 60e3) requests.delete(id);
  for (const [sid, exp] of sessions) if (exp < now) sessions.delete(sid);
}, 60e3).unref();

process.on('uncaughtException', (e) => console.error('Erreur non gérée :', e.message));
process.on('unhandledRejection', (e) => console.error('Promesse rejetée :', e && e.message));

server.listen(PORT, () => console.log('Serveur prêt sur le port ' + PORT));

// ---------- Pages ----------
const STYLE = `<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{--ink:#14232b;--bg:#eef2f4;--line:#c9d3d8;--accent:#0b6e6a}
*{box-sizing:border-box}
body{margin:0;font:16px/1.5 system-ui,sans-serif;color:var(--ink);background:var(--bg)}
main{max-width:34rem;margin:0 auto;padding:2rem 1.25rem}
h1{font-size:1.6rem;margin:0 0 1rem}
h2{font-size:1.1rem;margin:1.75rem 0 .5rem}
input,button{font:inherit;padding:.7rem .9rem;border-radius:6px;border:1px solid var(--line)}
input{width:100%}
button{background:var(--accent);color:#fff;border:0;cursor:pointer}
a.btn{display:block;text-align:center;text-decoration:none;background:var(--accent);color:#fff;padding:.9rem 1rem;border-radius:6px;margin-top:.75rem}
a.btn.alt{background:#fff;color:var(--accent);border:2px solid var(--accent)}
a:focus-visible,button:focus-visible,input:focus-visible{outline:3px solid #7cc4bf;outline-offset:2px}
#go,#in,#cp,#pause,#all{width:100%;margin-top:.75rem}
.item{display:block;width:100%;text-align:left;margin-top:.5rem;background:#fff;color:var(--ink);border:1px solid var(--line)}
.code{font-size:2.4rem;letter-spacing:.2em;font-weight:700}
.box,pre{background:#fff;border:1px solid var(--line);border-radius:6px;padding:1rem;margin-top:.75rem;word-break:break-all;font-family:ui-monospace,monospace;font-size:.85rem;white-space:pre-wrap}
.note{font-size:.9rem;color:#4a5b63}
.ok{color:var(--accent);font-weight:600}
.row{display:flex;gap:.5rem;align-items:center;padding:.5rem 0;border-bottom:1px solid var(--line)}
.row span{flex:1}
</style>`;

const HOME_HTML = `<!doctype html><html lang="fr"><title>Partage de connexion internet</title>${STYLE}
<main><h1>Partage de connexion internet</h1>
<p>Partagez votre connexion avec une personne de confiance, ou utilisez celle de quelqu’un, où que vous soyez.</p>
<a class="btn" href="/partager">Partager ma connexion</a>
<a class="btn alt" href="/connecter">Utiliser la connexion de quelqu’un</a>
<p class="note">Chaque demande est validée par la personne qui partage, qui peut couper l’accès à tout moment. Elle est responsable de l’usage fait de sa connexion : ne partagez qu’avec des personnes de confiance.</p></main></html>`;

const SHARE_HTML = `<!doctype html><html lang="fr"><title>Partager ma connexion</title>${STYLE}
<main><h1>Partager ma connexion</h1>
<div id="form"><p>Votre connexion sera utilisée par les personnes que vous aurez acceptées. Vous validez chaque demande et vous pouvez couper à tout moment. Vous êtes responsable de l’usage qui en est fait : ne partagez qu’avec des personnes de confiance.</p>
<input id="name" maxlength="30" placeholder="Nom affiché dans la liste (ex. : Téléphone de Marc)"><button id="go">Créer mon partage</button></div>
<div id="steps" hidden>
<h2>1. Installer Termux</h2><p>Sur Android, installez Termux depuis <b>f-droid.org</b> (la version du Play Store n’est plus à jour).</p>
<h2>2. Copier cette commande dans Termux</h2><p>Collez-la dans Termux et validez : tout s’installe, puis le partage démarre. Cela peut prendre quelques minutes.</p>
<pre id="cmd"></pre><button id="cp">Copier la commande</button>
<h2>3. Attendre la confirmation</h2><p id="state">En attente de votre téléphone…</p>
<p class="note">Gardez Termux ouvert et le téléphone branché. Ne montrez cette commande à personne : elle contient votre clé.</p>
<a class="btn alt" id="panel" href="#">Ouvrir mon tableau de bord</a></div>
<p id="msg" role="status"></p></main>
<script>
const $=id=>document.getElementById(id);
const post=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
$('go').onclick=async()=>{
  const name=$('name').value.trim();
  if(!name){$('msg').textContent='Choisissez un nom.';return}
  $('msg').textContent='Création…';
  let r;try{r=await post('/api/sharer/register',{name})}catch{$('msg').textContent='Serveur injoignable. Réessayez.';return}
  const s=await r.json();
  if(!r.ok){$('msg').textContent=s.error||'Erreur.';return}
  $('msg').textContent='';$('cmd').textContent=s.command;$('panel').href='/mon-partage#'+s.key;
  $('cp').onclick=()=>{navigator.clipboard.writeText(s.command);$('cp').textContent='Commande copiée'};
  $('form').hidden=true;$('steps').hidden=false;
  const t=setInterval(async()=>{
    let q;try{q=await (await post('/api/sharer/status',{key:s.key})).json()}catch{return}
    if(q.online){clearInterval(t);$('state').textContent='✅ Terminé : votre téléphone est en ligne et le nom « '+q.name+' » apparaît dans la liste.';$('state').className='ok'}
  },3000);
};
</script></html>`;

const CONNECT_HTML = `<!doctype html><html lang="fr"><title>Utiliser une connexion</title>${STYLE}
<main><h1>Utiliser la connexion de quelqu’un</h1>
<h2>1. L’application VPN (une seule fois)</h2>
<p>Sur Android, installez <b>v2rayNG</b> (version stable, fichier « arm64-v8a »). Sur Windows, installez <b>v2rayN</b>. N’utilisez pas une application d’un autre éditeur.</p>
<a class="btn alt" href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener">Télécharger v2rayNG</a>
<a class="btn alt" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener">Télécharger v2rayN</a>
<div id="pick"><h2>2. Choisir une connexion</h2><div id="list"><p>Chargement…</p></div></div>
<div id="form" hidden><h2>3. Votre nom</h2><p>Connexion demandée : <b id="who"></b></p><input id="name" maxlength="40" placeholder="Votre nom" autocomplete="name"><button id="go">Envoyer la demande</button></div>
<div id="wait" hidden><p>Donnez ce numéro à <b id="who2"></b> :</p><div class="code" id="code"></div><p>En attente de sa validation…</p></div>
<div id="done" hidden><h2>4. Connexion accordée</h2>
<p>Touchez le bouton : le lien s’ajoute dans l’application. Ensuite, sélectionnez-le et touchez le bouton de connexion.</p>
<a class="btn" id="open" href="#">Ouvrir dans l’application</a>
<p class="note">Si rien ne se passe, copiez le lien ci-dessous (il ne sera plus affiché) puis, dans l’application : « + », « Importer depuis le presse-papiers ».</p>
<div class="box" id="tok"></div><button id="cp">Copier le lien</button></div>
<p id="msg" role="status"></p></main>
<script>
const $=id=>document.getElementById(id);
let chosen=null,listTimer=null;
async function loadList(){
  let r;try{r=await (await fetch('/api/sharers')).json()}catch{return}
  if(!r.sharers.length){const p=document.createElement('p');p.textContent='Personne ne partage sa connexion pour le moment.';$('list').replaceChildren(p);return}
  $('list').replaceChildren(...r.sharers.map(s=>{const b=document.createElement('button');b.className='item';b.textContent=s.name;b.onclick=()=>choose(s);return b}));
}
function choose(s){chosen=s;clearInterval(listTimer);$('pick').hidden=true;$('form').hidden=false;$('who').textContent=s.name}
loadList();listTimer=setInterval(loadList,10000);
$('go').onclick=async()=>{
  const name=$('name').value.trim();
  if(!name){$('msg').textContent='Entrez votre nom.';return}
  $('msg').textContent='Envoi… (le serveur peut mettre une minute à se réveiller)';
  let r;
  try{r=await fetch('/api/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name,sharerId:chosen.id})})}catch{$('msg').textContent='Serveur injoignable. Réessayez.';return}
  const d=await r.json();
  if(!r.ok){$('msg').textContent=d.error||'Erreur.';return}
  $('form').hidden=true;$('wait').hidden=false;$('who2').textContent=d.sharer;$('code').textContent=d.id;$('msg').textContent='';
  const t=setInterval(async()=>{
    let s;
    try{s=await (await fetch('/api/status?id='+d.id+'&secret='+d.secret)).json()}catch{return}
    if(s.status==='pending')return;
    clearInterval(t);$('wait').hidden=true;
    if(s.status==='approved'){
      const h=location.host;
      const link='vless://'+s.token+'@'+h+':443?encryption=none&security=tls&sni='+h+'&type=ws&host='+h+'&path=%2Fvless#relais-maison';
      $('done').hidden=false;$('tok').textContent=link;
      $('open').href='v2rayng://install-sub/?url='+encodeURIComponent(location.origin+'/sub/'+s.token)+'%23relais-maison';
      $('cp').onclick=()=>{navigator.clipboard.writeText(link);$('cp').textContent='Lien copié'};
    }else $('msg').textContent=s.status==='rejected'?'Demande refusée.':'Demande expirée. Recommencez.';
  },3000);
};
</script></html>`;

const PANEL_HTML = `<!doctype html><html lang="fr"><title>Mon partage</title>${STYLE}
<main><h1>Mon partage</h1>
<section id="nokey" hidden><p>Entrez la clé de votre partage (elle est dans votre commande Termux, après « AGENT_KEY= »).</p><input id="k" placeholder="Votre clé"><button id="in">Ouvrir</button></section>
<section id="panel" hidden>
<p id="st"></p>
<button id="pause"></button>
<h2>Demandes en attente</h2><div id="pending"></div>
<h2>Personnes connectées</h2><div id="guests"></div>
<button id="all">Couper tout le monde</button></section>
<p id="msg" role="status"></p></main>
<script>
const $=id=>document.getElementById(id);
const api=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({key:KEY},b||{}))});
let KEY=(location.hash||'').slice(1)||sessionStorage.getItem('k')||'';
if(location.hash)history.replaceState(null,'',location.pathname);
if(KEY)sessionStorage.setItem('k',KEY);
let paused=false;
function row(text,btns){const d=document.createElement('div');d.className='row';const s=document.createElement('span');s.textContent=text;d.append(s);btns.forEach(([l,f])=>{const b=document.createElement('button');b.textContent=l;b.onclick=f;d.append(b)});return d}
async function act(p,b){const r=await api(p,b);$('msg').textContent=r.ok?'':((await r.json()).error||'Erreur.');refresh()}
async function refresh(){
  if(!KEY){$('nokey').hidden=false;$('panel').hidden=true;return}
  let r;try{r=await api('/api/mine/state')}catch{return}
  if(r.status===401){sessionStorage.removeItem('k');KEY='';$('nokey').hidden=false;$('panel').hidden=true;$('msg').textContent='Clé invalide.';return}
  const s=await r.json();$('nokey').hidden=true;$('panel').hidden=false;paused=s.paused;
  $('st').textContent=!s.known?'Votre téléphone ne s’est pas encore connecté au serveur.':(s.online?'Votre téléphone est en ligne ('+s.name+').':'Votre téléphone est hors ligne.')+(s.paused?' Partage en pause : votre nom n’est plus dans la liste.':'');
  $('pause').textContent=paused?'Reprendre le partage':'Mettre en pause (retirer de la liste)';
  $('pending').replaceChildren(...(s.pending.length?s.pending.map(p=>row(p.name+' (numéro '+p.id+')',[['Accepter',()=>act('/api/decision',{id:p.id,action:'approve'})],['Refuser',()=>act('/api/decision',{id:p.id,action:'reject'})]])):[row('Aucune demande.',[])]));
  $('guests').replaceChildren(...(s.guests.length?s.guests.map(g=>row(g.name+' ('+g.tunnels+' connexion(s))',[['Couper',()=>act('/api/revoke',{gid:g.gid})]])):[row('Personne pour le moment.',[])]));
}
$('in').onclick=()=>{KEY=$('k').value.trim();sessionStorage.setItem('k',KEY);refresh()};
$('pause').onclick=()=>act('/api/mine/pause',{paused:!paused});
$('all').onclick=()=>{if(confirm('Couper toutes les personnes connectées ?'))act('/api/revoke',{all:true})};
refresh();setInterval(()=>{if(!$('panel').hidden)refresh()},5000);
</script></html>`;

const ADMIN_HTML = `<!doctype html><html lang="fr"><title>Administration</title>${STYLE}
<main><h1>Administration</h1>
<section id="login"><input id="pw" type="password" autocomplete="current-password" placeholder="Mot de passe"><button id="in">Se connecter</button></section>
<section id="panel" hidden>
<h2>Partageurs</h2><div id="sharers"></div>
<h2>Demandes en attente</h2><div id="pending"></div>
<h2>Accès actifs</h2><div id="guests"></div>
<h2>Session</h2><button id="out">Se déconnecter</button></section>
<p id="msg" role="status"></p></main>
<script>
const $=id=>document.getElementById(id);
const api=(p,b)=>fetch(p,{method:b?'POST':'GET',headers:b?{'Content-Type':'application/json'}:{},body:b?JSON.stringify(b):undefined});
function row(text,btns){const d=document.createElement('div');d.className='row';const s=document.createElement('span');s.textContent=text;d.append(s);btns.forEach(([l,f])=>{const b=document.createElement('button');b.textContent=l;b.onclick=f;d.append(b)});return d}
async function act(p,b){const r=await api(p,b);$('msg').textContent=r.ok?'':((await r.json()).error||'Erreur.');refresh()}
async function refresh(){
  const r=await api('/api/admin/state');
  if(r.status===401){$('login').hidden=false;$('panel').hidden=true;return}
  const s=await r.json();$('login').hidden=true;$('panel').hidden=false;
  $('sharers').replaceChildren(...(s.sharers.length?s.sharers.map(h=>row(h.name+' : '+(h.online?'en ligne':'hors ligne')+(h.paused?', en pause':'')+', '+h.guests+' invité(s)',h.id==='owner'?[]:[['Retirer',()=>{if(confirm('Retirer ce partageur ?'))act('/api/admin/kick',{sid:h.id})}]])):[row('Aucun partageur connecté.',[])]));
  $('pending').replaceChildren(...(s.pending.length?s.pending.map(p=>row(p.name+' → '+p.sharer+' (numéro '+p.id+')',[['Accepter',()=>act('/api/decision',{id:p.id,action:'approve'})],['Refuser',()=>act('/api/decision',{id:p.id,action:'reject'})]])):[row('Aucune demande.',[])]));
  $('guests').replaceChildren(...(s.guests.length?s.guests.map(g=>row(g.name+' via '+g.sharer+' ('+g.tunnels+' connexion(s))',[['Couper',()=>act('/api/revoke',{gid:g.gid})]])):[row('Aucun accès actif.',[])]));
}
$('in').onclick=async()=>{const r=await api('/api/login',{password:$('pw').value});$('pw').value='';$('msg').textContent=r.ok?'':(await r.json()).error;refresh()};
$('out').onclick=async()=>{await api('/api/logout',{});refresh()};
refresh();setInterval(()=>{if(!$('panel').hidden)refresh()},5000);
</script></html>`;
