'use strict';
// Agent du téléphone relais. Lancement (voir start.sh) :
//   SERVER_URL=https://votre-service.onrender.com AGENT_KEY=votre_cle node agent.js
const fs = require('fs');
const path = require('path');
const net = require('net');
const dns = require('dns').promises;
const WebSocket = require('ws');

const SERVER = (process.env.SERVER_URL || '').replace(/\/$/, '');
const KEY = process.env.AGENT_KEY || '';
// Par défaut tous les ports sont permis sauf quelques ports sensibles (SSH, courrier sortant, partage Windows, bureau à distance)
const ALLOWED_PORTS = (process.env.ALLOWED_PORTS || '').split(',').filter(Boolean).map(Number);
const BLOCKED_PORTS = (process.env.BLOCKED_PORTS || '22,23,25,135,137,138,139,445,3389').split(',').map(Number);
const portOk = (p) => Number.isInteger(p) && (ALLOWED_PORTS.length ? ALLOWED_PORTS.includes(p) : !BLOCKED_PORTS.includes(p));
const DEBUG = process.env.DEBUG === '1';
const STORE = path.join(__dirname, 'guests.json'); // liste des invités (empreintes de jetons), jamais les jetons eux-mêmes
if (!SERVER || !KEY) {
  console.error('SERVER_URL et AGENT_KEY sont obligatoires.');
  process.exit(1);
}
const WS_BASE = SERVER.replace(/^http/, 'ws');

process.on('uncaughtException', (e) => console.error('Erreur non gérée :', e.message));
process.on('unhandledRejection', (e) => console.error('Promesse rejetée :', e && e.message));

// ---------- Liste des invités, conservée sur le téléphone ----------
function loadStore() {
  try {
    const a = JSON.parse(fs.readFileSync(STORE, 'utf8'));
    return Array.isArray(a) ? a : [];
  } catch { return []; }
}
function saveStore(list) {
  if (!Array.isArray(list) || list.length > 200) return;
  const tmp = STORE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(list), { mode: 0o600 });
  fs.renameSync(tmp, STORE);
}

// ---------- Refuse le réseau de la maison et la machine elle-même ----------
function isPrivate(ip) {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number);
    return a === 0 || a === 10 || a === 127 || a >= 224 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && b === 168);
  }
  const x = ip.toLowerCase();
  if (x === '::' || x === '::1') return true;
  if (/^f[cd]/.test(x) || /^fe[89ab]/.test(x)) return true;
  if (x.startsWith('::ffff:')) {
    const v4 = x.slice(7);
    return net.isIPv4(v4) ? isPrivate(v4) : true;
  }
  return false;
}

// ---------- Ouverture d'une connexion demandée par le serveur ----------
async function open(m, control) {
  const fail = () => { try { control.send(JSON.stringify({ t: 'fail', id: m.id })); } catch { /* ignoré */ } };
  if (DEBUG) console.log('Demande :', m.host + ':' + m.port);
  try {
    if (!/^[a-f0-9]{16}$/.test(m.id) || typeof m.host !== 'string' || !portOk(m.port)) throw new Error('refusé');
    let address;
    try { ({ address } = await dns.lookup(m.host, { family: 4 })); } // IPv4 d’abord : beaucoup de réseaux n’ont pas d’IPv6
    catch { ({ address } = await dns.lookup(m.host)); }
    if (isPrivate(address)) throw new Error('adresse privée refusée');

    const sock = net.connect({ host: address, port: m.port });
    sock.setTimeout(300000, () => sock.destroy());
    const ct = setTimeout(() => { console.error('Délai dépassé vers', m.host); sock.destroy(); }, 15000);
    sock.once('connect', () => clearTimeout(ct));
    sock.once('close', () => clearTimeout(ct));

    const ws = new WebSocket(`${WS_BASE}/agent-stream?id=${m.id}`, { headers: { 'x-agent-key': KEY } });
    const stream = WebSocket.createWebSocketStream(ws);
    const stop = () => { sock.destroy(); ws.terminate(); };
    sock.on('error', (e) => { console.error('Erreur de connexion à', m.host, ':', e.message); stop(); });
    stream.on('error', stop);
    ws.on('error', stop);
    ws.on('close', stop);
    sock.on('close', stop);
    sock.once('connect', () => { sock.pipe(stream); stream.pipe(sock); });
  } catch (e) {
    console.error('Refusé ou échec :', m.host, '-', e.message);
    fail();
  }
}

// ---------- Connexion de contrôle, avec détection des coupures silencieuses ----------
let delay = 2000;
function connect() {
  const ws = new WebSocket(`${WS_BASE}/agent`, { headers: { 'x-agent-key': KEY } });
  let lastPing = Date.now();
  let watchdog;

  ws.on('open', () => {
    delay = 2000;
    lastPing = Date.now();
    console.log('Connecté au serveur.');
    ws.send(JSON.stringify({ t: 'hello', guests: loadStore() }));
    watchdog = setInterval(() => {
      if (Date.now() - lastPing > 75000) { console.error('Serveur silencieux, reconnexion.'); ws.terminate(); }
    }, 15000);
  });
  ws.on('ping', () => { lastPing = Date.now(); });
  ws.on('message', (d) => {
    try {
      const m = JSON.parse(d);
      if (m.t === 'open') open(m, ws);
      else if (m.t === 'save') saveStore(m.guests);
    } catch (e) {
      console.error('Message ignoré :', e.message);
    }
  });
  ws.on('close', () => {
    clearInterval(watchdog);
    console.log(`Déconnecté, nouvelle tentative dans ${Math.round(delay / 1000)} s.`);
    setTimeout(connect, delay);
    delay = Math.min(delay * 1.5, 30000);
  });
  ws.on('error', () => {});
}
connect();

// Un appel régulier évite que le serveur gratuit s’endorme
setInterval(() => { fetch(SERVER + '/health').catch(() => {}); }, 5 * 60 * 1000);
