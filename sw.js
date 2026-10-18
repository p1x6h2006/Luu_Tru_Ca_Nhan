"use strict";
/* Service Worker: phát video bảo mật theo luồng.
   Video được mã hóa AES-GCM theo từng khúc 8 MB và lưu trong IndexedDB 'kho-ca-nhan-vid'.
   Khóa giải mã chỉ nằm trong bộ nhớ của worker, do trang gửi sang khi đã mở khóa, và bị xóa khi trang khóa lại.
   Mỗi yêu cầu Range chỉ giải mã đúng các khúc cần thiết, nên không tốn RAM theo kích thước video. */
const DB = 'kho-ca-nhan-vid', ST = 'vids', CS = 8 * 1048576;
let key = null, waiters = [], dbp = null;
const metaCache = new Map();

self.addEventListener('install', () => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('message', e => {
  const d = e.data || {};
  if (d.type === 'key' && d.key){ key = d.key; waiters.splice(0).forEach(f => f(key)); }
  else if (d.type === 'clear'){ key = null; metaCache.clear(); }
});

function getKey(){
  if (key) return Promise.resolve(key);
  return new Promise(res => {
    const t = setTimeout(() => res(null), 4000);
    waiters.push(k => { clearTimeout(t); res(k); });
    self.clients.matchAll({ includeUncontrolled:true }).then(cs => cs.forEach(c => c.postMessage({ type:'need-key' }))).catch(() => {});
  });
}
function db(){
  if (!dbp) dbp = new Promise((res, rej) => {
    const r = indexedDB.open(DB, 1);
    r.onupgradeneeded = () => r.result.createObjectStore(ST);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  }).catch(e => { dbp = null; throw e; });
  return dbp;
}
function get(k){
  return db().then(d => new Promise((res, rej) => {
    const q = d.transaction(ST).objectStore(ST).get(k);
    q.onsuccess = () => res(q.result); q.onerror = () => rej(q.error);
  }));
}
async function meta(id){
  let m = metaCache.get(id); if (m) return m;
  const r = await get(id); if (!r || !r.n) return null;
  const cs = r.cs || CS; let size = r.size;
  if (size == null){ const last = await get(id + '#' + (r.n - 1)); if (!last) return null; size = (r.n - 1) * cs + (last.ct.byteLength - 16); }
  m = { t:r.t || 'video/mp4', n:r.n, cs, size }; metaCache.set(id, m); return m;
}

self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.origin !== self.location.origin) return;
  const i = u.pathname.lastIndexOf('/__vid/'); if (i < 0) return;
  e.respondWith(serve(e.request, decodeURIComponent(u.pathname.slice(i + 7))));
});

async function serve(req, id){
  if (!/^[\w-]{3,40}$/.test(id)) return new Response('', { status:400 });
  const k = await getKey(); if (!k) return new Response('Locked', { status:401 });
  const m = await meta(id); if (!m) return new Response('Not found', { status:404 });
  let start = 0, end = m.size - 1, partial = false;
  const h = req.headers.get('range'), mm = h && /^bytes=(\d*)-(\d*)$/.exec(h);
  if (mm){
    if (mm[1] === ''){ start = Math.max(0, m.size - (+mm[2])); }
    else { start = +mm[1]; if (mm[2] !== '') end = Math.min(+mm[2], m.size - 1); }
    if (start > end || start >= m.size) return new Response('', { status:416, headers:{ 'Content-Range':'bytes */' + m.size } });
    partial = true;
  }
  let ci = Math.floor(start / m.cs), pos = start;
  const stream = new ReadableStream({
    async pull(ctl){
      if (!key){ ctl.error(new Error('locked')); return; }
      if (pos > end){ ctl.close(); return; }
      const c = await get(id + '#' + ci);
      if (!c){ ctl.error(new Error('missing')); return; }
      const plain = new Uint8Array(await crypto.subtle.decrypt({ name:'AES-GCM', iv:c.iv }, k, c.ct));
      const base = ci * m.cs, a = pos - base, b = Math.min(plain.length, end - base + 1);
      ctl.enqueue(plain.subarray(a, b)); pos = base + b; ci++;
      if (pos > end) ctl.close();
    }
  });
  const headers = { 'Content-Type':m.t, 'Content-Length':String(end - start + 1), 'Accept-Ranges':'bytes', 'Cache-Control':'no-store', 'Cross-Origin-Resource-Policy':'same-origin' };
  if (partial) headers['Content-Range'] = 'bytes ' + start + '-' + end + '/' + m.size;
  return new Response(stream, { status:partial ? 206 : 200, headers });
}
