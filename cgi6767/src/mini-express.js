// Mini router compatible con el uso que hace la CGI de Express (get/post/put/delete, :params, req.body/query/headers, res.json/status/set/send)
const compile = (path) => {
  const keys = [];
  const re = new RegExp('^' + path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&').replace(/:(\w+)/g, (_, k) => { keys.push(k); return '([^/]+)'; }) + '/?$');
  return { re, keys };
};

class Res {
  constructor() { this.code = 200; this.h = {}; this.body = ''; this.done = false; }
  status(c) { this.code = c; return this; }
  set(o) { Object.assign(this.h, o); return this; }
  json(o) { if (!this.h['Content-Type']) this.h['Content-Type'] = 'application/json; charset=utf-8'; this.body = JSON.stringify(o); this.done = true; return this; }
  send(b) { this.body = b; this.done = true; return this; }
}

const jerr = (code, e) => new Response(JSON.stringify({ e }), { status: code, headers: { 'Content-Type': 'application/json; charset=utf-8' } });

export function makeApp() {
  const routes = [];
  const add = (m) => (path, ...h) => { const c = compile(path); routes.push({ m, re: c.re, keys: c.keys, h: h.flat() }); };
  const app = { get: add('GET'), post: add('POST'), put: add('PUT'), delete: add('DELETE'), use() {} };

  app.handle = async (request) => {
    const url = new URL(request.url);
    let route = null, params = {};
    for (const r of routes) {
      if (r.m !== request.method) continue;
      const m = r.re.exec(url.pathname);
      if (m) { route = r; r.keys.forEach((k, i) => { try { params[k] = decodeURIComponent(m[i + 1]); } catch { params[k] = m[i + 1]; } }); break; }
    }
    if (!route) return jerr(404, 'No existe');

    const headers = {};
    request.headers.forEach((v, k) => { headers[k] = v; });
    // IP real del cliente (Cloudflare); se ignora cualquier x-forwarded-for enviado por el cliente
    headers['x-forwarded-for'] = request.headers.get('cf-connecting-ip') || '';

    let body = {};
    if (request.method !== 'GET') {
      const txt = await request.text();
      if (txt) { try { body = JSON.parse(txt); } catch { return jerr(400, 'JSON no válido'); } }
    }
    const q = { method: request.method, url: url.pathname, headers, params, query: Object.fromEntries(url.searchParams), body, socket: { remoteAddress: '' } };
    const s = new Res();
    try {
      let i = 0;
      const next = () => { const f = route.h[i++]; if (f) f(q, s, next); };
      next();
    } catch (e) {
      console.error('Error en', request.method, url.pathname, e && e.stack || e);
      return jerr(500, 'Error interno');
    }
    if (!s.done) return jerr(500, 'Sin respuesta');
    return new Response(s.body, { status: s.code, headers: s.h });
  };
  return app;
}
