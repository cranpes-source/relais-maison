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
// Adresses de téléchargement affichées sur les pages (à remplacer par vos fichiers hébergés dans une « Release » GitHub)
const TERMUX_URL = process.env.TERMUX_URL || 'https://f-droid.org/packages/com.termux/';
const VPN_URL = process.env.VPN_URL || 'https://github.com/2dust/v2rayNG/releases/latest';
const VPN_SHA256 = process.env.VPN_SHA256 || '';

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
    'pkg upgrade -y -o Dpkg::Options::=--force-confnew', // mise à jour complète : installer nodejs seul peut le casser
    'pkg install -y nodejs curl',
    `curl -fsSL ${origin}/install.sh | bash -s -- ${origin} ${key} '${name}'`,
  ].join(' && ');
}

// Jeton d’un invité : calculé à partir de son profil et du partageur, donc il peut être retrouvé à tout moment
function deriveToken(sid, uid) {
  const h = crypto.createHmac('sha256', SECRET).update(`guest:${sid}:${uid}`).digest();
  h[6] = (h[6] & 0x0f) | 0x40;
  h[8] = (h[8] & 0x3f) | 0x80;
  const x = h.subarray(0, 16).toString('hex');
  return `${x.slice(0, 8)}-${x.slice(8, 12)}-${x.slice(12, 16)}-${x.slice(16, 20)}-${x.slice(20)}`;
}

// Script lancé sur le téléphone du partageur par la commande Termux (aucune ${...} ici : c’est du texte brut)
const INSTALL_SH = String.raw`#!/data/data/com.termux/files/usr/bin/bash
# Installe le partage de connexion sur ce téléphone. Arguments : adresse du serveur, clé, nom.
ORIGIN="$1"; KEY="$2"; NAME="$3"
D="$HOME/partage"
mkdir -p "$D" && cd "$D" || exit 1
echo "Téléchargement du programme…"
curl -fsSL "$ORIGIN/agent.js" -o agent.js || { echo "Échec du téléchargement de agent.js"; exit 1; }
echo "Installation du module ws…"
npm install ws@8 --no-fund --no-audit --loglevel=error || { echo "Échec de l’installation du module ws"; exit 1; }
printf 'export SERVER_URL=%q\nexport AGENT_KEY=%q\nexport SHARER_NAME=%q\n' "$ORIGIN" "$KEY" "$NAME" > config.env
chmod 600 config.env

cat > start.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Démarre le partage en arrière-plan (une seule instance à la fois).
cd "$(dirname "$0")" || exit 1
. ./config.env
pkill -f 'node agent.js' 2>/dev/null
sleep 1
termux-wake-lock 2>/dev/null
: > agent.log
nohup bash -c 'while true; do node agent.js; [ $? -eq 99 ] && break; sleep 3; done' >> agent.log 2>&1 &
echo "Démarrage du partage…"
for i in $(seq 1 45); do
  grep -q "Terminé" agent.log 2>/dev/null && break
  sleep 1
done
cat agent.log
echo
echo "Le partage tourne en arrière-plan : vous pouvez utiliser votre téléphone normalement."
echo "Arrêter : bash ~/partage/stop.sh      État : bash ~/partage/status.sh"
EOF

cat > stop.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Arrête le partage : votre nom disparaît de la liste.
pkill -f 'node agent.js' 2>/dev/null
termux-wake-unlock 2>/dev/null
echo "Partage arrêté."
EOF

cat > status.sh <<'EOF'
#!/data/data/com.termux/files/usr/bin/bash
# Indique si le partage tourne et affiche les dernières lignes du journal.
if pgrep -f 'node agent.js' > /dev/null; then echo "Le partage est ACTIF."; else echo "Le partage est ARRÊTÉ."; fi
tail -n 5 "$(dirname "$0")/agent.log" 2>/dev/null
EOF
chmod +x start.sh stop.sh status.sh

# Démarrage automatique au redémarrage du téléphone (nécessite l’application Termux:Boot)
mkdir -p "$HOME/.termux/boot"
printf '#!/data/data/com.termux/files/usr/bin/bash\nbash %s/start.sh\n' "$D" > "$HOME/.termux/boot/partage"
chmod +x "$HOME/.termux/boot/partage"

bash "$D/start.sh"
`;

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
    if (p === '/install.sh') return send(res, 200, INSTALL_SH, 'text/plain');
    if (p === '/api/config') return send(res, 200, { termuxUrl: TERMUX_URL, vpnUrl: VPN_URL, vpnSha256: VPN_SHA256 });

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
  // Un profil = un identifiant + une clé, pour partager comme pour utiliser une connexion
  if (p === '/api/account/create' || p === '/api/sharer/register') {
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

  if (p === '/api/account/command') {
    const uid = identify(body.key);
    const name = cleanName(body.name, 30);
    if (!uid) return send(res, 401, { error: 'clé invalide' });
    if (!name) return send(res, 400, { error: 'nom requis' });
    return send(res, 200, { command: termuxCommand(originOf(publicHost(req)), body.key, name) });
  }

  if (p === '/api/account/mine') { // les connexions que ce profil a le droit d’utiliser
    const uid = identify(body.key);
    if (!uid) return send(res, 401, { error: 'clé invalide' });
    const accesses = [];
    for (const s of sharers.values()) {
      if (s.id !== uid && guests.has(hex(deriveToken(s.id, uid)))) accesses.push({ sharerId: s.id, name: s.name, online: online(s) && !s.paused });
    }
    return send(res, 200, { id: uid, accesses });
  }

  if (p === '/api/account/link') { // retrouver son jeton à tout moment, tant que l’accès n’est pas coupé
    const uid = identify(body.key);
    if (!uid) return send(res, 401, { error: 'clé invalide' });
    const sid = String(body.sharerId);
    const token = deriveToken(sid, uid);
    if (!guests.has(hex(token))) return send(res, 404, { error: 'Aucun accès accordé pour cette connexion.' });
    return send(res, 200, { token, sharer: nameOf(sid) });
  }

  if (p === '/api/account/leave') { // renoncer soi-même à un accès
    const uid = identify(body.key);
    if (!uid) return send(res, 401, { error: 'clé invalide' });
    const sid = String(body.sharerId);
    const h = hex(deriveToken(sid, uid));
    if (!guests.has(h)) return send(res, 404, { error: 'Aucun accès accordé pour cette connexion.' });
    if (!online(sharers.get(sid))) return send(res, 503, { error: 'Le téléphone du partageur est hors ligne : réessayez dans un instant.' });
    dropGuest(h);
    persist(sid);
    return send(res, 200, { ok: true });
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
    const uid = body.key ? identify(body.key) : null;
    if (body.key && !uid) return send(res, 401, { error: 'clé invalide' });
    if (uid === s.id) return send(res, 400, { error: 'C’est votre propre connexion.' });
    if (uid && guests.has(hex(deriveToken(s.id, uid)))) return send(res, 200, { already: true, sharer: s.name });
    const name = cleanName(body.name, 40);
    if (!name) return send(res, 400, { error: 'nom requis' });
    const open = [...requests.values()].filter((r) => r.status === 'pending');
    if (open.length >= 100 || open.filter((r) => r.sid === s.id).length >= 10) return send(res, 429, { error: 'trop de demandes' });
    let id;
    do { id = String(crypto.randomInt(100000, 1000000)); } while (requests.has(id));
    const secret = rand(16);
    requests.set(id, { sid: s.id, uid, name, secret, status: 'pending', token: null, createdAt: Date.now() });
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

  if (p === '/api/mine/stop') { // arrête le programme sur le téléphone du partageur
    const s = who.sid && sharers.get(who.sid);
    if (!online(s)) return send(res, 409, { error: 'Votre téléphone est déjà hors ligne.' });
    try { s.ws.send(JSON.stringify({ t: 'stop' })); } catch { return send(res, 500, { error: 'Envoi impossible.' }); }
    return send(res, 200, { ok: true });
  }

  if (p === '/api/decision') {
    const r = requests.get(String(body.id));
    if (!r || r.status !== 'pending' || (!who.admin && r.sid !== who.sid)) return send(res, 404, { error: 'demande introuvable' });
    if (body.action === 'approve') {
      const s = sharers.get(r.sid);
      if (!online(s)) return send(res, 503, { error: 'Le téléphone du partageur est hors ligne : réessayez dans un instant.' });
      if ([...guests.values()].filter((g) => g.sid === r.sid).length >= 100) return send(res, 429, { error: 'Trop d’invités pour ce partageur.' });
      const token = r.uid ? deriveToken(r.sid, r.uid) : crypto.randomUUID();
      const th = hex(token);
      if (guests.has(th)) guests.get(th).name = r.name;
      else guests.set(th, { sid: r.sid, gid: rand(4), name: r.name, since: Date.now(), tunnels: new Set() });
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
#go,#in,#cp,#pause,#all,button.w{width:100%;margin-top:.75rem}
button.alt2{background:#fff;color:var(--accent);border:2px solid var(--accent)}
.item{display:block;width:100%;text-align:left;margin-top:.5rem;background:#fff;color:var(--ink);border:1px solid var(--line)}
.code{font-size:2.4rem;letter-spacing:.2em;font-weight:700}
.box,pre{background:#fff;border:1px solid var(--line);border-radius:6px;padding:1rem;margin-top:.75rem;word-break:break-all;font-family:ui-monospace,monospace;font-size:.85rem;white-space:pre-wrap}
.note{font-size:.9rem;color:#4a5b63}
.ok{color:var(--accent);font-weight:600}
.row{display:flex;gap:.5rem;align-items:center;padding:.5rem 0;border-bottom:1px solid var(--line)}
.row span{flex:1}
</style>`;

const COMMON_JS = `
const $=id=>document.getElementById(id);
const post=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
function getAcct(){try{return JSON.parse(localStorage.getItem('acct')||'null')}catch(e){return null}}
function setAcct(a){localStorage.setItem('acct',JSON.stringify(a))}
`;

const HOME_HTML = `<!doctype html><html lang="fr"><title>Partage de connexion internet</title>${STYLE}
<main><h1>Partage de connexion internet</h1>
<div id="new"><p>Partagez votre connexion avec une personne de confiance, ou utilisez celle de quelqu’un, où que vous soyez. Pour commencer, choisissez un nom : un identifiant personnel et une clé vous sont créés, ils servent pour partager comme pour utiliser une connexion.</p>
<input id="name" maxlength="30" placeholder="Votre nom" autocomplete="name"><button class="w" id="go">Créer mon profil</button>
<h2>Vous avez déjà une clé ?</h2><p class="note">Tapez votre nom ci-dessus, collez votre clé ici et retrouvez votre profil sur cet appareil.</p>
<input id="k" placeholder="Votre clé personnelle"><button class="w alt2" id="restore">Retrouver mon profil</button></div>
<div id="me" hidden><p>Bonjour <b id="nm"></b>. Votre identifiant : <b id="uid"></b></p>
<a class="btn" href="/partager">Partager ma connexion</a>
<a class="btn alt" href="/connecter">Utiliser la connexion de quelqu’un</a>
<h2>Ma clé personnelle</h2><p class="note">Gardez-la : elle permet de retrouver votre profil sur un autre appareil. Ne la montrez à personne.</p>
<button class="w" id="showkey">Afficher et copier ma clé</button><div class="box" id="keybox" hidden></div>
<button class="w alt2" id="logout">Changer de profil sur cet appareil</button></div>
<p class="note">Chaque demande est validée par la personne qui partage, qui peut couper l’accès à tout moment. Elle est responsable de l’usage fait de sa connexion : ne partagez qu’avec des personnes de confiance.</p>
<p id="msg" role="status"></p></main>
<script>${COMMON_JS}
function showKey(){const a=getAcct();$('keybox').hidden=false;$('keybox').textContent=a.key}
function render(){const a=getAcct();$('new').hidden=!!a;$('me').hidden=!a;if(a){$('nm').textContent=a.name;$('uid').textContent=a.id}}
$('go').onclick=async()=>{
  const name=$('name').value.trim();
  if(!name){$('msg').textContent='Choisissez un nom.';return}
  $('msg').textContent='Création…';
  let r;try{r=await post('/api/account/create',{name})}catch(e){$('msg').textContent='Serveur injoignable. Réessayez.';return}
  const d=await r.json();
  if(!r.ok){$('msg').textContent=d.error||'Erreur.';return}
  setAcct({name:d.name,id:d.id,key:d.key});$('msg').textContent='';render();showKey();
};
$('restore').onclick=async()=>{
  const key=$('k').value.trim(),name=$('name').value.trim();
  if(!key||!name){$('msg').textContent='Tapez votre nom et collez votre clé.';return}
  let r;try{r=await post('/api/account/mine',{key})}catch(e){$('msg').textContent='Serveur injoignable.';return}
  const d=await r.json();
  if(!r.ok){$('msg').textContent='Clé invalide.';return}
  setAcct({name,id:d.id,key});$('msg').textContent='';render();
};
$('showkey').onclick=()=>{showKey();if(navigator.clipboard)navigator.clipboard.writeText(getAcct().key);$('showkey').textContent='Clé copiée'};
$('logout').onclick=()=>{if(confirm('Retirer ce profil de cet appareil ? Gardez votre clé pour le retrouver.')){localStorage.removeItem('acct');render()}};
render();
</script></html>`;

const SHARE_HTML = `<!doctype html><html lang="fr"><title>Partager ma connexion</title>${STYLE}
<main><h1>Partager ma connexion</h1>
<p>Votre connexion sera utilisée par les personnes que vous aurez acceptées. Vous validez chaque demande et vous pouvez couper à tout moment. Vous êtes responsable de l’usage qui en est fait.</p>
<h2>1. Installer Termux (une seule fois)</h2>
<p>Termux est l’application qui fait tourner le partage sur Android. Installez la version téléchargée ci-dessous, pas celle du Play Store. Android demandera d’autoriser l’installation depuis votre navigateur : acceptez.</p>
<a class="btn alt" id="dl" href="#" target="_blank" rel="noopener">Télécharger Termux</a>
<h2>2. Copier cette commande dans Termux</h2><p>Ouvrez Termux, collez la commande et validez. Tout s’installe puis le partage démarre : cela peut prendre quelques minutes.</p>
<pre id="cmd">Préparation…</pre><button class="w" id="cp">Copier la commande</button>
<h2>3. Attendre la confirmation</h2><p id="state">En attente de votre téléphone…</p>
<h2>4. Ensuite</h2>
<p>Le partage <b>tourne en arrière-plan</b> : quittez Termux et utilisez votre téléphone normalement. Pour qu’Android ne le coupe pas, ouvrez Réglages, Applications, Termux, Batterie, puis choisissez « Sans restriction ».</p>
<p><b>Arrêter le partage :</b> dans Termux, tapez <code>bash ~/partage/stop.sh</code>, ou utilisez le bouton ci-dessous. <b>Voir l’état :</b> <code>bash ~/partage/status.sh</code>. Ne tapez pas « exit » dans Termux : cela arrêterait tout.</p>
<button class="w alt2" id="stop">Arrêter le partage sur mon téléphone</button>
<a class="btn alt" href="/mon-partage">Ouvrir mon tableau de bord</a>
<p id="msg" role="status"></p></main>
<script>${COMMON_JS}
const A=getAcct();if(!A)location.href='/';
fetch('/api/config').then(r=>r.json()).then(c=>{$('dl').href=c.termuxUrl}).catch(()=>{});
(async()=>{
  const r=await post('/api/account/command',{key:A.key,name:A.name});const d=await r.json();
  if(!r.ok){$('cmd').textContent=d.error||'Erreur.';return}
  $('cmd').textContent=d.command;
  $('cp').onclick=()=>{navigator.clipboard.writeText(d.command);$('cp').textContent='Commande copiée'};
})();
const t=setInterval(async()=>{
  let q;try{q=await (await post('/api/sharer/status',{key:A.key})).json()}catch(e){return}
  if(q.online){$('state').textContent='✅ Terminé : votre téléphone est en ligne et le nom « '+q.name+' » apparaît dans la liste.';$('state').className='ok'}
  else{$('state').textContent='En attente de votre téléphone…';$('state').className=''}
},3000);
$('stop').onclick=async()=>{
  if(!confirm('Arrêter le partage sur votre téléphone ? Votre nom disparaîtra de la liste.'))return;
  const r=await post('/api/mine/stop',{key:A.key});$('msg').textContent=r.ok?'Arrêt demandé : le programme s’arrête sur votre téléphone.':((await r.json()).error||'Erreur.');
};
</script></html>`;

const CONNECT_HTML = `<!doctype html><html lang="fr"><title>Utiliser une connexion</title>${STYLE}
<main><h1>Utiliser la connexion de quelqu’un</h1>
<h2>1. L’application VPN (une seule fois)</h2>
<p>Installez l’application ci-dessous (Android). Elle fonctionne en arrière-plan : une fois connecté, vous utilisez votre téléphone normalement. Android demandera d’autoriser l’installation depuis votre navigateur : acceptez.</p>
<a class="btn alt" id="dl" href="#" target="_blank" rel="noopener">Télécharger l’application VPN</a>
<p class="note" id="sha"></p>
<div id="mine" hidden><h2>Mes connexions</h2><div id="minelist"></div></div>
<div id="pick"><h2>2. Choisir une connexion</h2><div id="list"><p>Chargement…</p></div></div>
<div id="wait" hidden><p>Donnez ce numéro à <b id="who2"></b> :</p><div class="code" id="code"></div><p>En attente de sa validation…</p></div>
<div id="done" hidden><h2>3. Connexion accordée</h2>
<p>Touchez le bouton : le lien s’ajoute dans l’application. Ensuite, sélectionnez-le et touchez le bouton de connexion. <b>Pour arrêter</b> : touchez ■ dans l’application, ou le bouton de sa notification.</p>
<a class="btn" id="open" href="#">Ouvrir dans l’application</a>
<p class="note">Si rien ne se passe, copiez le lien ci-dessous puis, dans l’application : « + », « Import from Clipboard ».</p>
<div class="box" id="tok"></div><button class="w" id="cp">Copier le lien</button></div>
<p id="msg" role="status"></p></main>
<script>${COMMON_JS}
const A=getAcct();if(!A)location.href='/';
fetch('/api/config').then(r=>r.json()).then(c=>{$('dl').href=c.vpnUrl;if(c.vpnSha256)$('sha').textContent='Empreinte SHA-256 du fichier : '+c.vpnSha256}).catch(()=>{});
let listTimer=null;
function showLink(token){
  clearInterval(listTimer);$('pick').hidden=true;$('wait').hidden=true;$('mine').hidden=true;$('done').hidden=false;
  const h=location.host;
  const link='vless://'+token+'@'+h+':443?encryption=none&security=tls&sni='+h+'&type=ws&host='+h+'&path=%2Fvless#relais-maison';
  $('tok').textContent=link;
  $('open').href='v2rayng://install-sub/?url='+encodeURIComponent(location.origin+'/sub/'+token)+'%23relais-maison';
  $('cp').onclick=()=>{navigator.clipboard.writeText(link);$('cp').textContent='Lien copié'};
}
async function loadMine(){
  let d;try{d=await (await post('/api/account/mine',{key:A.key})).json()}catch(e){return}
  if(!d.accesses||!d.accesses.length){$('mine').hidden=true;return}
  $('mine').hidden=false;
  $('minelist').replaceChildren(...d.accesses.map(x=>{
    const row=document.createElement('div');row.className='row';
    const sp=document.createElement('span');sp.textContent=x.name+(x.online?'':' (hors ligne)');row.append(sp);
    const b=document.createElement('button');b.textContent='Obtenir mon lien';
    b.onclick=async()=>{const r=await post('/api/account/link',{key:A.key,sharerId:x.sharerId});const q=await r.json();if(r.ok)showLink(q.token);else $('msg').textContent=q.error||'Erreur.'};
    row.append(b);
    const l=document.createElement('button');l.textContent='Retirer';l.className='alt2';
    l.onclick=async()=>{if(!confirm('Renoncer à cet accès ?'))return;const r=await post('/api/account/leave',{key:A.key,sharerId:x.sharerId});$('msg').textContent=r.ok?'':((await r.json()).error||'Erreur.');loadMine()};
    row.append(l);return row;
  }));
}
async function loadList(){
  let r;try{r=await (await fetch('/api/sharers')).json()}catch(e){return}
  const others=r.sharers.filter(s=>s.id!==A.id);
  if(!others.length){const p=document.createElement('p');p.textContent='Personne ne partage sa connexion pour le moment.';$('list').replaceChildren(p);return}
  $('list').replaceChildren(...others.map(s=>{const b=document.createElement('button');b.className='item';b.textContent=s.name;b.onclick=()=>choose(s);return b}));
}
async function choose(s){
  clearInterval(listTimer);$('msg').textContent='Envoi de la demande… (le serveur peut mettre une minute à se réveiller)';
  let r;try{r=await post('/api/request',{key:A.key,name:A.name,sharerId:s.id})}catch(e){$('msg').textContent='Serveur injoignable. Réessayez.';listTimer=setInterval(loadList,10000);return}
  const d=await r.json();
  if(!r.ok){$('msg').textContent=d.error||'Erreur.';listTimer=setInterval(loadList,10000);return}
  if(d.already){const q=await (await post('/api/account/link',{key:A.key,sharerId:s.id})).json();showLink(q.token);$('msg').textContent='';return}
  $('pick').hidden=true;$('mine').hidden=true;$('wait').hidden=false;$('who2').textContent=d.sharer;$('code').textContent=d.id;$('msg').textContent='';
  const t=setInterval(async()=>{
    let st;try{st=await (await fetch('/api/status?id='+d.id+'&secret='+d.secret)).json()}catch(e){return}
    if(st.status==='pending')return;
    clearInterval(t);
    if(st.status==='approved'||st.status==='delivered'){
      const q=await (await post('/api/account/link',{key:A.key,sharerId:s.id})).json();
      if(q.token){showLink(q.token);return}
    }
    $('wait').hidden=true;$('msg').textContent=st.status==='rejected'?'Demande refusée.':'Demande expirée. Recommencez.';
  },3000);
}
loadMine();loadList();listTimer=setInterval(loadList,10000);
</script></html>`;

const PANEL_HTML = `<!doctype html><html lang="fr"><title>Mon partage</title>${STYLE}
<main><h1>Mon partage</h1>
<section id="nokey" hidden><p>Votre profil n’est pas sur cet appareil. Collez votre clé personnelle.</p><input id="k" placeholder="Votre clé"><button id="in">Ouvrir</button></section>
<section id="panel" hidden>
<p id="st"></p>
<button id="pause"></button>
<h2>Demandes en attente</h2><div id="pending"></div>
<h2>Personnes connectées</h2><div id="guests"></div>
<button id="all">Couper tout le monde</button>
<h2>Arrêter le partage</h2>
<p class="note">Le programme tourne en arrière-plan sur votre téléphone. Pour l’arrêter : dans Termux, <code>bash ~/partage/stop.sh</code>, ou le bouton ci-dessous.</p>
<button class="w alt2" id="stop">Arrêter le programme sur mon téléphone</button></section>
<p id="msg" role="status"></p></main>
<script>
const $=id=>document.getElementById(id);
let acct=null;try{acct=JSON.parse(localStorage.getItem('acct')||'null')}catch(e){}
let KEY=(location.hash||'').slice(1)||(acct&&acct.key)||sessionStorage.getItem('k')||'';
if(location.hash)history.replaceState(null,'',location.pathname);
if(KEY)sessionStorage.setItem('k',KEY);
const api=(p,b)=>fetch(p,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(Object.assign({key:KEY},b||{}))});
let paused=false;
function row(text,btns){const d=document.createElement('div');d.className='row';const s=document.createElement('span');s.textContent=text;d.append(s);btns.forEach(([l,f])=>{const b=document.createElement('button');b.textContent=l;b.onclick=f;d.append(b)});return d}
async function act(p,b){const r=await api(p,b);$('msg').textContent=r.ok?'':((await r.json()).error||'Erreur.');refresh()}
async function refresh(){
  if(!KEY){$('nokey').hidden=false;$('panel').hidden=true;return}
  let r;try{r=await api('/api/mine/state')}catch(e){return}
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
$('stop').onclick=()=>{if(confirm('Arrêter le programme sur votre téléphone ? Votre nom disparaîtra de la liste.'))act('/api/mine/stop',{})};
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
