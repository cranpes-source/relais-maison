'use strict';
// Client local. Lancement :
//   SERVER_URL=https://votre-service.onrender.com TOKEN=votre_jeton node client.js
// Puis réglez le proxy HTTPS de votre navigateur sur 127.0.0.1:8080
const http = require('http');
const WebSocket = require('ws');

const SERVER = (process.env.SERVER_URL || '').replace(/\/$/, '');
const TOKEN = process.env.TOKEN || '';
const LOCAL_PORT = Number(process.env.LOCAL_PORT || 8080);
if (!SERVER || !TOKEN) {
  console.error('SERVER_URL et TOKEN sont obligatoires.');
  process.exit(1);
}
const WS_BASE = SERVER.replace(/^http/, 'ws');

const proxy = http.createServer((req, res) => {
  res.writeHead(405);
  res.end('Seul le HTTPS (CONNECT) est pris en charge.');
});

proxy.on('connect', (req, clientSocket, head) => {
  const m = /^(.+):(\d+)$/.exec(req.url);
  if (!m) return clientSocket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
  const ws = new WebSocket(`${WS_BASE}/tunnel?host=${encodeURIComponent(m[1])}&port=${m[2]}`, { headers: { 'x-token': TOKEN } });
  const stream = WebSocket.createWebSocketStream(ws);
  const stop = () => { clientSocket.destroy(); ws.terminate(); };
  stream.on('error', stop);
  ws.on('error', stop);
  ws.on('close', stop);
  clientSocket.on('error', stop);
  clientSocket.on('close', stop);
  clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
  if (head && head.length) stream.write(head);
  clientSocket.pipe(stream);
  stream.pipe(clientSocket);
});

proxy.listen(LOCAL_PORT, '127.0.0.1', () => console.log(`Proxy prêt sur 127.0.0.1:${LOCAL_PORT}`));
