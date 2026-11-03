'use strict';
// Agent du téléphone relais. Lancement :
//   SERVER_URL=https://votre-service.onrender.com AGENT_KEY=votre_cle node agent.js
const net = require('net');
const dns = require('dns').promises;
const WebSocket = require('ws');

const SERVER = (process.env.SERVER_URL || '').replace(/\/$/, '');
const KEY = process.env.AGENT_KEY || '';
const ALLOWED_PORTS = (process.env.ALLOWED_PORTS || '80,443').split(',').map(Number);
if (!SERVER || !KEY) {
  console.error('SERVER_URL et AGENT_KEY sont obligatoires.');
  process.exit(1);
}
const WS_BASE = SERVER.replace(/^http/, 'ws');

// Refuse tout ce qui pointe vers le réseau de la maison ou la machine elle-même
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

async function open(m, control) {
  const fail = () => { try { control.send(JSON.stringify({ t: 'fail', id: m.id })); } catch { /* ignoré */ } };
  console.log('Demande :', m.host + ':' + m.port);
  try {
    if (!/^[a-f0-9]{16}$/.test(m.id) || typeof m.host !== 'string' || !ALLOWED_PORTS.includes(m.port)) throw new Error('refusé');
    const { address } = await dns.lookup(m.host);
    if (isPrivate(address)) throw new Error('adresse privée refusée');

    const sock = net.connect({ host: address, port: m.port });
    sock.setTimeout(300000, () => sock.destroy());
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

function connect() {
  const ws = new WebSocket(`${WS_BASE}/agent`, { headers: { 'x-agent-key': KEY } });
  ws.on('open', () => console.log('Connecté au serveur.'));
  ws.on('message', (d) => {
    try {
      const m = JSON.parse(d);
      if (m.t === 'open') open(m, ws);
    } catch { /* ignoré */ }
  });
  ws.on('close', () => { console.log('Déconnecté, nouvelle tentative dans 5 s.'); setTimeout(connect, 5000); });
  ws.on('error', () => {});
}
connect();

// Un appel régulier évite que le serveur gratuit s’endorme
setInterval(() => { fetch(SERVER + '/health').catch(() => {}); }, 10 * 60 * 1000);
