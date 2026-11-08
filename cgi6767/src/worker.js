import { DurableObject } from 'cloudflare:workers';
import { createCore } from './core.js';

// Todo el backend vive en UN Durable Object (con SQLite): los datos son persistentes y consistentes.
export class CGI extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.core = createCore(ctx.storage.sql, env);
  }
  async fetch(request) {
    return this.core.handle(request);
  }
}

// Los archivos de /public los sirve Cloudflare directamente; aquí solo llegan las peticiones /api/*
export default {
  async fetch(request, env) {
    const stub = env.CGI.get(env.CGI.idFromName('principal'), { locationHint: 'weur' });
    return stub.fetch(request);
  },
};
