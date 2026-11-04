'use strict';
const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = process.env.PORT || 3000;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const AGENT_KEY = process.env.AGENT_KEY || '';
if (ADMIN_PASSWORD.length < 12 || AGENT_KEY.length < 24) {
  console.error('ADMIN_PASSWORD (12 caractères min.) et AGENT_KEY (24 caractères min.) sont obligatoires.');
  process.exit(1);
}

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const rand = (n) => crypto.randomBytes(n).toString('hex');
const hex = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');

// Les demandes et sessions restent en mémoire. La liste des invités (empreintes des jetons, jamais les jetons)
// est sauvegardée sur le téléphone relais et rechargée quand il se reconnecte après un redémarrage du serveur.
const sessions = new Map(); // sid -> expiration
const requests = new Map(); // numéro à 6 chiffres -> demande
const guests = new Map();   // empreinte du jeton -> { gid, name, since, tunnels }
const waiting = new Map();  // id de tunnel -> { stream, ws, timer }
let agent = null;           // connexion du téléphone relais
let loaded = false;         // la liste des invités a-t-elle été rechargée depuis le téléphone ?
let failures = 0;
let lockedUntil = 0;

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

function snapshot() {
  return [...guests.entries()].map(([h, g]) => ({ h, gid: g.gid, name: g.name, since: g.since }));
}
function persist() {
  if (!agent) return false;
  try { agent.send(JSON.stringify({ t: 'save', guests: snapshot() })); return true; } catch { return false; }
}
function loadGuests(list) {
  if (!Array.isArray(list)) return;
  for (const g of list.slice(0, 200)) {
    if (g && /^[a-f0-9]{64}$/.test(g.h) && /^[a-f0-9]{8}$/.test(g.gid) && typeof g.name === 'string' && !guests.has(g.h)) {
      guests.set(g.h, { gid: g.gid, name: g.name.slice(0, 40), since: Number(g.since) || Date.now(), tunnels: new Set() });
    }
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;

  if (req.method === 'GET') {
    if (p === '/health') return send(res, 200, 'ok', 'text/plain');
    if (p === '/' || p === '/demande') return send(res, 200, GUEST_HTML, 'text/html');
    if (p === '/admin') return send(res, 200, ADMIN_HTML, 'text/html');
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
        agentOnline: Boolean(agent),
        pending: [...requests.entries()]
          .filter(([, r]) => r.status === 'pending')
          .map(([id, r]) => ({ id, name: r.name })),
        guests: [...guests.values()].map((g) => ({ gid: g.gid, name: g.name, tunnels: g.tunnels.size })),
      });
    }
    return send(res, 404, { error: 'introuvable' });
  }

  if (req.method !== 'POST') return send(res, 405, { error: 'méthode refusée' });
  const body = await readJson(req);
  if (!body) return send(res, 400, { error: 'requête invalide' });

  if (p === '/api/request') {
    if (typeof body.name !== 'string' || !body.name.trim()) return send(res, 400, { error: 'nom requis' });
    const open = [...requests.values()].filter((r) => r.status === 'pending').length;
    if (open >= 20) return send(res, 429, { error: 'trop de demandes' });
    let id;
    do { id = String(crypto.randomInt(100000, 1000000)); } while (requests.has(id));
    const secret = rand(16);
    requests.set(id, { name: body.name.trim().slice(0, 40), secret, status: 'pending', token: null, createdAt: Date.now() });
    return send(res, 200, { id, secret });
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

  if (!isAdmin(req)) return send(res, 401, { error: 'non autorisé' });

  if (p === '/api/logout') {
    const m = /(?:^|; )sid=([a-f0-9]{48})/.exec(req.headers.cookie || '');
    if (m) sessions.delete(m[1]);
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/decision') {
    const r = requests.get(String(body.id));
    if (!r || r.status !== 'pending') return send(res, 404, { error: 'demande introuvable' });
    if (body.action === 'approve') {
      if (!agent) return send(res, 503, { error: 'Le téléphone relais est hors ligne : réessayez dans un instant.' });
      const token = crypto.randomUUID();
      guests.set(hex(token), { gid: rand(4), name: r.name, since: Date.now(), tunnels: new Set() });
      persist();
      r.status = 'approved';
      r.token = token;
    } else {
      r.status = 'rejected';
    }
    return send(res, 200, { ok: true });
  }

  if (p === '/api/admin/revoke') {
    if (!agent) return send(res, 503, { error: 'Le téléphone relais est hors ligne : la révocation doit y être enregistrée. Réessayez dans un instant.' });
    for (const [h, g] of guests) {
      if (g.gid === body.gid) {
        guests.delete(h);
        for (const ws of g.tunnels) ws.terminate();
      }
    }
    persist();
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

    if (h.cmd === 2 && h.port === 53) {
      phase = 'dns';
      ws.send(Buffer.from([0, 0]), { binary: true });
      return dnsFrames(h.rest);
    }
    if (h.cmd !== 1 || !agent || !/^[a-zA-Z0-9.-]{1,253}$/.test(h.host)) return done();

    phase = 'connecting';
    if (h.rest.length) pending.push(h.rest);
    wid = rand(8);
    const timer = setTimeout(() => { waiting.delete(wid); done(); }, 10000);
    waiting.set(wid, {
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
    agent.send(JSON.stringify({ t: 'open', id: wid, host: h.host, port: h.port }));
  });
}

server.on('upgrade', (req, socket, head) => {
  const refuse = (status) => { socket.write(`HTTP/1.1 ${status}\r\nConnection: close\r\n\r\n`); socket.destroy(); };
  const url = new URL(req.url, 'http://x');
  const h = req.headers;
  const agentOk = typeof h['x-agent-key'] === 'string' && same(h['x-agent-key'], AGENT_KEY);

  // Le téléphone relais garde cette connexion ouverte et reçoit les demandes d’ouverture
  if (url.pathname === '/agent') {
    if (!agentOk) return refuse('401 Unauthorized');
    return upgrade(req, socket, head, (ws) => {
      if (agent) agent.terminate();
      agent = ws;
      ws.on('message', (d) => {
        try {
          const m = JSON.parse(d);
          if (m.t === 'hello') {
            if (!loaded) { loadGuests(m.guests); loaded = true; }
            persist();
            return;
          }
          const w = waiting.get(m.id);
          if (m.t === 'fail' && w) { waiting.delete(m.id); clearTimeout(w.timer); w.ws.terminate(); }
        } catch { /* ignoré */ }
      });
      ws.on('close', () => { if (agent === ws) agent = null; });
    });
  }

  // Le téléphone relais ouvre un flux par connexion demandée
  if (url.pathname === '/agent-stream') {
    const id = url.searchParams.get('id') || '';
    const w = waiting.get(id);
    if (!agentOk || !w) return refuse('404 Not Found');
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
    const host = url.searchParams.get('host') || '';
    const port = Number(url.searchParams.get('port'));
    if (!g) return refuse('401 Unauthorized');
    if (!agent) return refuse('503 Service Unavailable');
    if (!/^[a-zA-Z0-9.-]{1,253}$/.test(host) || !Number.isInteger(port) || port < 1 || port > 65535 || g.tunnels.size >= 300) {
      return refuse('400 Bad Request');
    }
    return upgrade(req, socket, head, (ws) => {
      if (!agent) return ws.terminate();
      const stream = WebSocket.createWebSocketStream(ws); // met en mémoire les données reçues avant l’appairage
      const id = rand(8);
      const timer = setTimeout(() => { waiting.delete(id); ws.terminate(); }, 10000);
      waiting.set(id, { stream, ws, timer });
      g.tunnels.add(ws);
      ws.on('close', () => { g.tunnels.delete(ws); clearTimeout(timer); waiting.delete(id); });
      stream.on('error', () => ws.terminate());
      try { agent.send(JSON.stringify({ t: 'open', id, host, port })); } catch { ws.terminate(); }
    });
  }

  // Applications VPN existantes (v2rayNG, v2rayN…) : protocole VLESS sur WebSocket
  if (url.pathname === '/vless') {
    if (!agent) return refuse('503 Service Unavailable');
    return upgrade(req, socket, head, (ws) => handleVless(ws));
  }

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
main{max-width:32rem;margin:0 auto;padding:2rem 1.25rem}
h1{font-size:1.6rem;margin:0 0 1rem}
h2{font-size:1.1rem;margin:1.75rem 0 .5rem}
input,button{font:inherit;padding:.7rem .9rem;border-radius:6px;border:1px solid var(--line)}
input{width:100%}
button{background:var(--accent);color:#fff;border:0;cursor:pointer}
button:focus-visible,input:focus-visible{outline:3px solid #7cc4bf;outline-offset:2px}
#go,#in,#cp{width:100%;margin-top:.75rem}
.code{font-size:2.4rem;letter-spacing:.2em;font-weight:700}
.box{background:#fff;border:1px solid var(--line);border-radius:6px;padding:1rem;margin-top:1rem;word-break:break-all;font-family:ui-monospace,monospace;font-size:.9rem}
.row{display:flex;gap:.5rem;align-items:center;padding:.5rem 0;border-bottom:1px solid var(--line)}
.row span{flex:1}
</style>`;

const GUEST_HTML = `<!doctype html><html lang="fr"><title>Demander l’accès</title>${STYLE}
<main><h1>Demander l’accès</h1>
<div id="form"><p>Entrez votre nom. Vous recevrez un numéro à communiquer au propriétaire, qui validera votre demande.</p>
<input id="name" maxlength="40" placeholder="Votre nom" autocomplete="name"><button id="go">Envoyer la demande</button></div>
<div id="wait" hidden><p>Donnez ce numéro au propriétaire :</p><div class="code" id="code"></div><p>En attente de validation…</p></div>
<div id="done" hidden><p>Accès accordé. Copiez ce lien maintenant : il ne sera plus affiché. Dans l’application VPN, choisissez « Importer depuis le presse-papiers ».</p><div class="box" id="tok"></div><button id="cp">Copier le lien</button></div>
<p id="msg" role="status"></p></main>
<script>
const $=id=>document.getElementById(id);
$('go').onclick=async()=>{
  const name=$('name').value.trim();
  if(!name){$('msg').textContent='Entrez votre nom.';return}
  $('msg').textContent='Envoi… (le serveur peut mettre une minute à se réveiller)';
  let r;
  try{r=await fetch('/api/request',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})})}catch{$('msg').textContent='Serveur injoignable. Réessayez.';return}
  if(!r.ok){$('msg').textContent='Trop de demandes en cours. Réessayez plus tard.';return}
  const {id,secret}=await r.json();
  $('form').hidden=true;$('wait').hidden=false;$('code').textContent=id;$('msg').textContent='';
  const t=setInterval(async()=>{
    let s;
    try{s=await (await fetch('/api/status?id='+id+'&secret='+secret)).json()}catch{return}
    if(s.status==='pending')return;
    clearInterval(t);$('wait').hidden=true;
    if(s.status==='approved'){const h=location.host;$('done').hidden=false;$('tok').textContent='vless://'+s.token+'@'+h+':443?encryption=none&security=tls&sni='+h+'&type=ws&host='+h+'&path=%2Fvless#relais-maison';$('cp').onclick=()=>{navigator.clipboard.writeText($('tok').textContent);$('cp').textContent='Lien copié'}}
    else $('msg').textContent=s.status==='rejected'?'Demande refusée.':'Demande expirée. Recommencez.';
  },3000);
};
</script></html>`;

const ADMIN_HTML = `<!doctype html><html lang="fr"><title>Administration</title>${STYLE}
<main><h1>Administration</h1>
<section id="login"><input id="pw" type="password" autocomplete="current-password" placeholder="Mot de passe"><button id="in">Se connecter</button></section>
<section id="panel" hidden>
<p id="agent"></p>
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
  $('agent').textContent=s.agentOnline?'Téléphone relais : connecté':'Téléphone relais : hors ligne';
  $('pending').replaceChildren(...(s.pending.length?s.pending.map(p=>row(p.name+' (numéro '+p.id+')',[['Accepter',()=>act('/api/admin/decision',{id:p.id,action:'approve'})],['Refuser',()=>act('/api/admin/decision',{id:p.id,action:'reject'})]])):[row('Aucune demande.',[])]));
  $('guests').replaceChildren(...(s.guests.length?s.guests.map(g=>row(g.name+' ('+g.tunnels+' connexion(s))',[['Révoquer',()=>act('/api/admin/revoke',{gid:g.gid})]])):[row('Aucun accès actif.',[])]));
}
$('in').onclick=async()=>{const r=await api('/api/login',{password:$('pw').value});$('pw').value='';$('msg').textContent=r.ok?'':(await r.json()).error;refresh()};
$('out').onclick=async()=>{await api('/api/logout',{});refresh()};
refresh();setInterval(()=>{if(!$('panel').hidden)refresh()},5000);
</script></html>`;
