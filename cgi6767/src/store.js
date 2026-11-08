// Almacenamiento persistente sobre SQLite de Durable Objects.
// Cada elemento (usuario, nota, ficha...) es una fila; los valores grandes se trocean (límite de ~2 MB por fila).
import crypto from 'node:crypto';

const CHUNK = 400000;
const ARR_LIGHT = ['users', 'reports'];
const ARR_HEAVY = ['notes', 'fichas', 'invs'];
const sha = (s) => crypto.createHash('sha1').update(s).digest('hex');

export class Store {
  constructor(sql) {
    this.sql = sql;
    sql.exec('CREATE TABLE IF NOT EXISTS items(coll TEXT NOT NULL, id TEXT NOT NULL, part INTEGER NOT NULL, v TEXT NOT NULL, PRIMARY KEY(coll,id,part))');
    this.cache = {};
    this.logN = 0;
  }

  _rows(where = '', ...p) {
    return this.sql.exec(`SELECT coll,id,part,v FROM items ${where} ORDER BY coll, CAST(id AS INTEGER), id, part`, ...p).toArray();
  }
  _group(rows) {
    const out = {};
    let cur = null;
    for (const r of rows) {
      const k = r.coll + '\u0000' + r.id;
      if (!cur || cur.k !== k) { cur = { k, coll: r.coll, id: r.id, v: '' }; (out[r.coll] ||= []).push(cur); }
      cur.v += r.v;
    }
    return out;
  }

  load() {
    const g = this._group(this._rows("WHERE coll NOT IN ('sess','secret')"));
    const D = {
      users: [], logs: [], notes: [], reports: [], invs: [], fichas: [],
      settings: { name: 'Comisaría General de Información', welcome: 'Acceso autorizado' },
      seq: { u: 0, n: 0, r: 0, i: 0, l: 0 },
    };
    for (const c of [...ARR_LIGHT, ...ARR_HEAVY, 'logs']) {
      D[c] = (g[c] || []).map((x) => JSON.parse(x.v));
      const m = (this.cache[c] = new Map());
      if (c !== 'logs') D[c].forEach((it, i) => m.set(String(it.id), sha(g[c][i].v)));
    }
    this.logN = D.logs.length;
    for (const x of g.meta || []) { D[x.id] = JSON.parse(x.v); (this.cache.meta ||= new Map()).set(x.id, sha(x.v)); }
    return D;
  }

  _write(coll, id, json) {
    this.sql.exec('DELETE FROM items WHERE coll=? AND id=?', coll, id);
    for (let i = 0, p = 0; i < json.length || p === 0; i += CHUNK, p++) {
      this.sql.exec('INSERT INTO items(coll,id,part,v) VALUES(?,?,?,?)', coll, id, p, json.slice(i, i + CHUNK));
      if (json.length === 0) break;
    }
  }
  _obj(name, o) {
    const j = JSON.stringify(o), h = sha(j), c = (this.cache.meta ||= new Map());
    if (c.get(name) !== h) { this._write('meta', name, j); c.set(name, h); }
  }
  _arr(coll, arr) {
    const c = (this.cache[coll] ||= new Map()), seen = new Set();
    for (const it of arr) {
      const id = String(it.id), j = JSON.stringify(it), h = sha(j);
      seen.add(id);
      if (c.get(id) !== h) { this._write(coll, id, j); c.set(id, h); }
    }
    for (const id of [...c.keys()]) if (!seen.has(id)) { this.sql.exec('DELETE FROM items WHERE coll=? AND id=?', coll, id); c.delete(id); }
  }

  // light: ajustes, contadores, usuarios, informes y logs nuevos. all: además notas, fichas e investigaciones (las que llevan imágenes)
  flush(D, all) {
    this._obj('settings', D.settings);
    this._obj('seq', D.seq);
    for (const c of ARR_LIGHT) this._arr(c, D[c]);
    for (; this.logN < D.logs.length; this.logN++) this._write('logs', String(D.logs[this.logN].id), JSON.stringify(D.logs[this.logN]));
    if (all) for (const c of ARR_HEAVY) this._arr(c, D[c]);
  }

  loadSess() {
    const now = Date.now(), out = [];
    for (const r of this._rows("WHERE coll='sess'")) {
      try { const v = JSON.parse(r.v); if (now - v.t < 18e5) out.push([r.id, v]); else this.sql.exec("DELETE FROM items WHERE coll='sess' AND id=?", r.id); } catch {}
    }
    return out;
  }
  putSess(tk, v) { this._write('sess', tk, JSON.stringify(v)); }
  delSess(tk) { this.sql.exec("DELETE FROM items WHERE coll='sess' AND id=?", tk); }

  getSecret(name) { const r = this._rows("WHERE coll='secret' AND id=?", name)[0]; return r ? r.v : null; }
  putSecret(name, v) { this._write('secret', name, v); }
}
