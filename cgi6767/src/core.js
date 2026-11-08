// CGI · Andalucía RP — lógica del servidor (uso exclusivo del servidor de rol Andalucía RP, no oficial)
// Versión para Cloudflare Workers + Durable Object (SQLite): los datos persisten aunque el servidor se reinicie.
import crypto from 'node:crypto';
import { makeApp } from './mini-express.js';
import { Store } from './store.js';

export function createCore(sql, env = {}) {
const C = crypto;
const R={Alumno:1,Analista:2,Coordinador:3,'Secretario General':4,'Comisario General':5,'Facciones Legales':6,Desarrollador:7,UCO:0,UAIL:0,FGE:0};
const store = new Store(sql);
const D = store.load();
const save = () => store.flush(D, false), saveAll = () => store.flush(D, true);
// Sesiones (persistentes: no se pierden cuando el servidor se "duerme")
const S = {
  m: new Map(store.loadSess()),
  get(k) { return this.m.get(k); },
  set(k, v) { v.pt = Date.now(); this.m.set(k, v); store.putSess(k, { id: v.id, t: v.t }); },
  delete(k) { if (this.m.delete(k)) store.delSess(k); },
  touch(k, v) { if (Date.now() - (v.pt || 0) > 6e4) { v.pt = Date.now(); store.putSess(k, { id: v.id, t: v.t }); } },
};
const hash=(p,s=C.randomBytes(16).toString('hex'))=>({s,h:C.pbkdf2Sync(p,s,30000,32,'sha256').toString('hex')});
const chk=(p,u)=>{const a=Buffer.from(C.pbkdf2Sync(p,u.s,30000,32,'sha256').toString('hex')),b=Buffer.from(u.h);return a.length==b.length&&C.timingSafeEqual(a,b)};
// Clave de cifrado de contraseñas recuperables: variable CGI_KEY o, si no existe, una clave aleatoria guardada en la base de datos
let K;
if(env.CGI_KEY)K=C.createHash('sha256').update(String(env.CGI_KEY)).digest();
else{let kx=store.getSecret('key');if(!kx){kx=C.randomBytes(32).toString('hex');store.putSecret('key',kx)}K=Buffer.from(kx,'hex')}
// Contraseñas recuperables SOLO por el Desarrollador: cifradas con AES-256-GCM (la clave vive en secret.key o en la variable CGI_KEY, no en data.json)
const enc=p=>{try{const iv=C.randomBytes(12),c=C.createCipheriv('aes-256-gcm',K,iv),d=Buffer.concat([c.update(p,'utf8'),c.final()]);return Buffer.concat([iv,c.getAuthTag(),d]).toString('base64')}catch(e){return ''}};
const dec=e=>{try{const b=Buffer.from(e,'base64'),d=C.createDecipheriv('aes-256-gcm',K,b.subarray(0,12));d.setAuthTag(b.subarray(12,28));return Buffer.concat([d.update(b.subarray(28)),d.final()]).toString('utf8')}catch(x){return null}};
const setPw=(u,p)=>{Object.assign(u,hash(p));u.pe=enc(p)};
// Cuenta de Desarrollador inicial: se crea si no existe. Para restablecerla (si te quedas sin acceso) pon DEV_RESET = "1" en wrangler.jsonc, despliega y quítalo después.
const DEV_USER='dev',DEV_PASS='CGI-Dev#2026!Atlas';
{let d=D.users.find(u=>u.user.toLowerCase()===DEV_USER);
if(!d){d={id:++D.seq.u,user:DEV_USER,discord:'',role:'Desarrollador',name:'Desarrollador CGI',plate:'000',inv:[]};D.users.push(d);setPw(d,DEV_PASS);saveAll()}
else if(env.DEV_RESET==='1'){setPw(d,DEV_PASS);d.role='Desarrollador';d.susp=false;saveAll()}}

const HOOK=/^https:\/\/(discord|discordapp)\.com\/api\/webhooks\//;
// Avisos al canal de Discord (webhook): solo si el Desarrollador ha configurado la URL
const hook=(a,d,u)=>{const h=D.settings.hook;if(!h||!HOOK.test(h)||typeof fetch!='function')return;fetch(h,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({embeds:[{title:String(a).slice(0,200),description:String(d||'—').slice(0,1500),color:/FALLIDO|BLOQUEADO|SUSPEND|ELIMINAD/i.test(a)?0xc8102e:0x0a3a82,footer:{text:u?`${u.name} · ${u.role}${u.plate?' · '+u.plate:''}`:'Sin identificar'},timestamp:new Date().toISOString()}]})}).catch(()=>{})};
const FL=new Map(),ip=r=>String(r.headers['x-forwarded-for']||r.socket.remoteAddress||'').split(',')[0].trim();
const pub=u=>({id:u.id,user:u.user,discord:u.discord,role:u.role,name:u.name,plate:u.plate,inv:u.inv||[],susp:!!u.susp});
const nm=id=>(D.users.find(u=>u.id==id)||{name:'(eliminado)'}).name;
const staff=u=>R[u.role]>=1&&R[u.role]<6;
const L=(q,type,act,det,inv)=>{const u=q.u;D.logs.push({id:++D.seq.l,ts:new Date().toISOString(),type,act,det:det||'',inv:inv||null,user:u?u.user:(q.lu||'—'),name:u?u.name:'',role:u?u.role:'',plate:u?u.plate:'',ip:ip(q)});if(/FALLIDO|BLOQUEADO|SUSPEND|ELIMINAD|creada|creado|enviado|asociado|Cambio de mando|Ajustes|Copia|reactivada/i.test(act))hook(act,det,u);save()};
const inInv=(i,u)=>i.lead==u.id||i.team.includes(u.id)||(R[u.role]===0&&(u.inv||[]).includes(i.id)),vis=(i,u)=>inInv(i,u)||R[u.role]>=4;
const mg=(i,u)=>i.lead==u.id||R[u.role]>=6;
const ed=(i,u)=>mg(i,u)||i.team.includes(u.id),edI=(i,u)=>i.lead==u.id||R[u.role]>=4;
const canR=(r,u)=>R[u.role]>=3||r.by==u.id||(r.shared||[]).includes(u.id)||(r.inv&&D.invs.some(i=>i.id==r.inv&&inInv(i,u)));
const nOk=(n,u)=>!n.cls||n.by==u.user||R[u.role]>=(n.cls==1?3:4);
const can=(q,role)=>R[role]!==undefined&&(R[role]>=6?q.lv>=7:q.lv>=5);
const E=(s,m,c)=>s.status(c||400).json({e:m});

const app=makeApp();
const auth=(min=0)=>(q,s,n)=>{const k=(q.headers.authorization||'').slice(7),ss=S.get(k),u=ss&&Date.now()-ss.t<18e5&&D.users.find(x=>x.id==ss.id&&!x.susp);if(!u){S.delete(k);return E(s,'Sesión no válida',401)}ss.t=Date.now();S.touch(k,ss);q.u=u;q.lv=R[u.role];if(q.lv<min)return E(s,'Sin permisos',403);n()};

// ---------- Sesión ----------
app.post('/api/login',(q,s)=>{const{u,p}=q.body||{},x=D.users.find(a=>a.user.toLowerCase()===String(u||'').toLowerCase()),k=ip(q),f=FL.get(k)||{n:0,t:0},rec=Date.now()-f.t<6e5;q.lu=String(u||'').slice(0,40);
if(f.n>=8&&rec){L(q,'auth','Inicio de sesión BLOQUEADO','Demasiados intentos fallidos desde esta IP');return E(s,'Demasiados intentos. Espera 10 minutos.',429)}
if(!x||!chk(String(p||''),x)){FL.set(k,{n:(rec?f.n:0)+1,t:Date.now()});L(q,'auth','Intento de inicio de sesión FALLIDO',x?'Contraseña incorrecta':'Usuario inexistente');return E(s,'Usuario o contraseña incorrectos',401)}
FL.delete(k);if(x.susp){L(q,'auth','Intento de acceso con cuenta SUSPENDIDA','');return E(s,'Cuenta suspendida. Contacta con el mando.',403)}const tk=C.randomBytes(24).toString('hex');S.set(tk,{id:x.id,t:Date.now()});q.u=x;L(q,'auth','Inicio de sesión correcto','');s.json({tk,me:pub(x)})});
app.post('/api/logout',auth(),(q,s)=>{L(q,'auth','Cierre de sesión');S.delete(q.headers.authorization.slice(7));s.json({})});
app.get('/api/me',auth(),(q,s)=>s.json(pub(q.u)));
app.put('/api/me',auth(),(q,s)=>{const b=q.body,u=q.u;if(!chk(String(b.cur||''),u)){L(q,'auth','Intento fallido de edición de cuenta propia','Contraseña actual incorrecta');return E(s,'La contraseña actual no es correcta')}
const ch=[],nu=String(b.user||'').trim();
if(nu&&nu!==u.user){if(D.users.some(x=>x.id!=u.id&&x.user.toLowerCase()==nu.toLowerCase()))return E(s,'Ese usuario ya existe');u.user=nu;ch.push('usuario')}
if(b.pass){if(String(b.pass).length<6)return E(s,'La contraseña debe tener al menos 6 caracteres');setPw(u,String(b.pass));ch.push('contraseña')}
if(!ch.length)return E(s,'No has cambiado nada');L(q,'usuarios','Edición de cuenta propia','Ha editado: '+ch.join(' y '));saveAll();s.json(pub(u))});
// Ajustes de la web (lectura pública para el login; solo Desarrollador puede cambiarlos)
app.get('/api/settings',(q,s)=>s.json({name:D.settings.name,welcome:D.settings.welcome}));
app.get('/api/settings/hook',auth(7),(q,s)=>s.json({hook:D.settings.hook||''}));
app.get('/api/backup',auth(7),(q,s)=>{L(q,'dev','Copia de seguridad descargada','data.json completo');s.set({'Content-Type':'application/json','Content-Disposition':`attachment; filename="cgi-backup-${new Date().toISOString().slice(0,10)}.json"`}).send(JSON.stringify(D))});
app.put('/api/settings',auth(7),(q,s)=>{const n=String(q.body.name||'').trim().slice(0,60),w=String(q.body.welcome||'').trim().slice(0,100);if(!n)return E(s,'El nombre del portal no puede estar vacío');
const h=String(q.body.hook||'').trim();if(h&&!HOOK.test(h))return E(s,'El webhook debe ser una URL de webhook de Discord');
D.settings={name:n,welcome:w||'Acceso autorizado',hook:h};L(q,'dev','Ajustes de la web modificados',`nombre: ${n} | bienvenida: ${D.settings.welcome} | webhook de Discord: ${h?'configurado':'desactivado'}`);if(h)hook('Webhook conectado','✅ El registro de la CGI enviará avisos a este canal.');saveAll();s.json({name:n,welcome:D.settings.welcome})});
app.get('/api/stats',auth(),(q,s)=>s.json({inv:D.invs.filter(i=>vis(i,q.u)).length,notes:q.lv?D.notes.length:0,reports:D.reports.filter(r=>canR(r,q.u)).length,members:D.users.filter(staff).length}));
app.get('/api/dir',auth(1),(q,s)=>s.json(D.users.filter(u=>R[u.role]<6).map(u=>({id:u.id,name:u.name,plate:u.plate,role:u.role,discord:u.discord}))));

// ---------- Perfiles ----------
app.get('/api/users',auth(5),(q,s)=>{const dev=q.query.scope=='dev';if(dev&&q.lv<7)return E(s,'Sin permisos',403);s.json(D.users.filter(u=>dev||R[u.role]<6).map(u=>{const x=pub(u);if(q.lv<7)delete x.user;return x}))});
app.post('/api/users',auth(5),(q,s)=>{const b=q.body;if(!can(q,b.role))return E(s,'No puedes gestionar ese rango',403);
if(!b.user||!b.pass||!b.name)return E(s,'Usuario, contraseña y nombre completo son obligatorios');
if(D.users.some(x=>x.user.toLowerCase()==String(b.user).toLowerCase()))return E(s,'Ese usuario ya existe');
const u={id:++D.seq.u,user:String(b.user).trim(),...hash(String(b.pass)),pe:enc(String(b.pass)),discord:b.discord||'',role:b.role,name:b.name,plate:b.plate||'',inv:R[b.role]===0?(b.inv||[]).map(Number):[]};
D.users.push(u);L(q,R[u.role]>=6?'dev':'usuarios','Perfil creado',`${u.name} · ${u.role} · placa ${u.plate}`);saveAll();s.json(pub(u))});
app.put('/api/users/:id',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id),b=q.body;if(!u)return E(s,'No existe',404);
if(!can(q,u.role)||!can(q,b.role||u.role))return E(s,'No puedes gestionar ese rango',403);
if(u.id==q.u.id&&b.role&&b.role!==u.role)return E(s,'No puedes cambiar tu propio rango');
if(b.user&&q.lv>=7&&b.user.toLowerCase()!=u.user.toLowerCase()&&D.users.some(x=>x.user.toLowerCase()==b.user.toLowerCase()))return E(s,'Ese usuario ya existe');
const ch=[];(q.lv>=7?['user','discord','name','plate','role']:['discord','name','plate','role']).forEach(k=>{if(b[k]!==undefined&&b[k]!==u[k]){ch.push(k=='user'?'usuario modificado':`${k}: ${u[k]} → ${b[k]}`);u[k]=b[k]}});
if(b.pass&&q.lv>=7){setPw(u,String(b.pass));ch.push('contraseña modificada')}
if(R[u.role]===0&&b.inv){u.inv=b.inv.map(Number);ch.push('accesos a investigaciones: '+u.inv.join(','))}
L(q,R[u.role]>=6?'dev':'usuarios','Perfil editado',`${u.name}: ${ch.join(' | ')||'sin cambios'}`);saveAll();s.json(pub(u))});
app.put('/api/users/:id/susp',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);if(!can(q,u.role))return E(s,'No puedes gestionar ese rango',403);if(u.id==q.u.id)return E(s,'No puedes suspenderte a ti mismo');
u.susp=!!q.body.susp;L(q,R[u.role]>=6?'dev':'usuarios',u.susp?'Cuenta SUSPENDIDA':'Cuenta reactivada',`${u.name} · ${u.role}`);saveAll();s.json(pub(u))});
app.get('/api/users/:id/secret',auth(7),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);L(q,'dev','Contraseña consultada por el Desarrollador',`Perfil: ${u.name}`);s.json({pass:u.pe?dec(u.pe):null})});
app.delete('/api/users/:id',auth(5),(q,s)=>{const u=D.users.find(x=>x.id==q.params.id);if(!u)return E(s,'No existe',404);
if(!can(q,u.role))return E(s,'No puedes gestionar ese rango',403);if(u.id==q.u.id)return E(s,'No puedes eliminar tu propio perfil');
D.users=D.users.filter(x=>x!==u);D.invs.forEach(i=>{i.team=i.team.filter(x=>x!=u.id)});L(q,R[u.role]>=6?'dev':'usuarios','Perfil eliminado',`${u.name} · ${u.role}`);saveAll();s.json({})});

// ---------- Logs (solo lectura: no existe ninguna ruta para editar o borrar) ----------
const flt=(Q,lv)=>{const{q:t,type,user,inv,from,to}=Q;let a=D.logs.map(l=>lv>=7?l:{...l,user:l.name||'(no identificado)'});
if(type)a=a.filter(l=>l.type==type);if(user)a=a.filter(l=>l.user==user);if(inv)a=a.filter(l=>l.inv==inv);
if(from)a=a.filter(l=>l.ts.slice(0,10)>=from);if(to)a=a.filter(l=>l.ts.slice(0,10)<=to);
if(t){const w=t.toLowerCase();a=a.filter(l=>JSON.stringify(l).toLowerCase().includes(w))}
return a};
app.get('/api/logs',auth(3),(q,s)=>{const a=flt(q.query,q.lv);s.json({total:a.length,rows:a.slice(-500).reverse(),users:[...new Set(flt({},q.lv).map(l=>l.user))],invs:D.invs.map(i=>({id:i.id,name:i.name}))})});
// Exportación CSV (respeta los filtros; las celdas que empiezan por = + - @ se neutralizan)
app.get('/api/logs/export',auth(3),(q,s)=>{const a=flt(q.query,q.lv).slice().reverse(),c=v=>{v=String(v??'');if(/^[=+\-@\t\r]/.test(v))v="'"+v;return '"'+v.replace(/"/g,'""')+'"'};
const csv=['id,fecha_utc,tipo,usuario,nombre,rango,placa,accion,detalle,ip',...a.map(l=>[l.id,l.ts,l.type,l.user,l.name,l.role,l.plate,l.act,l.det,l.ip].map(c).join(','))].join('\r\n');
L(q,'logs','Logs exportados a CSV',`${a.length} registro(s)`);s.set({'Content-Type':'text/csv; charset=utf-8','Content-Disposition':'attachment; filename="logs-cgi.csv"'}).send('\ufeff'+csv)});

// ---------- Notas informativas ----------
app.get('/api/notes',auth(1),(q,s)=>{const w=(q.query.q||'').toLowerCase();s.json(D.notes.filter(n=>nOk(n,q.u)&&(!w||`${n.id} ${n.event} ${n.byName}`.toLowerCase().includes(w))).reverse().map(n=>({id:n.id,num:n.id,when:n.when,event:n.event,byName:n.byName,files:n.files.length,cls:n.cls||0})))});
app.get('/api/notes/:id',auth(1),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id);n&&nOk(n,q.u)?s.json({...n,num:n.id}):E(s,'No existe',404)});
app.post('/api/notes',auth(1),(q,s)=>{const b=q.body;if(!b.when||!b.event)return E(s,'Indica día/hora y suceso');
const files=(b.files||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,12);
const n={id:++D.seq.n,cls:[1,2].includes(+b.cls)?+b.cls:0,when:b.when,event:String(b.event).slice(0,6000),files,by:q.u.user,byName:`${q.u.name} (${q.u.plate})`,ts:new Date().toISOString()};
D.notes.push(n);L(q,'notas','Nota informativa creada',`Nº ${n.id} · ${files.length} archivo(s)`);saveAll();s.json({id:n.id})});
app.delete('/api/notes/:id',auth(3),(q,s)=>{const n=D.notes.find(x=>x.id==q.params.id);if(!n||!nOk(n,q.u))return E(s,'No existe',404);
D.notes=D.notes.filter(x=>x!==n);L(q,'notas','Nota informativa ELIMINADA',`Nº ${n.id} de ${n.byName}: ${n.event.slice(0,120)}`);saveAll();s.json({})});

// ---------- Base de datos común: personas, bandas y vehículos ----------
const FT=['Persona','Banda','Vehículo'];
const fv=(q,s)=>{const b=q.body;if(!b.name){E(s,'Indica el nombre');return null}if(!FT.includes(b.type)){E(s,'Tipo no válido');return null}
return{type:b.type,name:String(b.name).slice(0,80),alias:String(b.alias||'').slice(0,80),plate:String(b.plate||'').slice(0,20),op:String(b.op||'').slice(0,120),notes:String(b.notes||'').slice(0,1500),files:(b.files||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,6)}};
app.get('/api/fichas',auth(1),(q,s)=>{const w=(q.query.q||'').toLowerCase(),t=q.query.t;s.json(D.fichas.filter(f=>(!t||f.type==t)&&(!w||`${f.name} ${f.alias} ${f.plate} ${f.op} ${f.notes}`.toLowerCase().includes(w))).reverse().map(f=>({...f,files:f.files.slice(0,1)})))});
app.get('/api/fichas/:id',auth(1),(q,s)=>{const f=D.fichas.find(x=>x.id==q.params.id);f?s.json(f):E(s,'No existe',404)});
app.post('/api/fichas',auth(2),(q,s)=>{const v=fv(q,s);if(!v)return;const f={id:D.seq.f=(D.seq.f||0)+1,...v,by:q.u.name,ts:new Date().toISOString()};D.fichas.push(f);L(q,'fichas','Ficha creada',`${f.type}: ${f.name}`);saveAll();s.json({id:f.id})});
app.put('/api/fichas/:id',auth(2),(q,s)=>{const f=D.fichas.find(x=>x.id==q.params.id);if(!f)return E(s,'No existe',404);const v=fv(q,s);if(!v)return;Object.assign(f,v);L(q,'fichas','Ficha editada',`${f.type}: ${f.name}`);saveAll();s.json({})});
app.delete('/api/fichas/:id',auth(3),(q,s)=>{const f=D.fichas.find(x=>x.id==q.params.id);if(!f)return E(s,'No existe',404);D.fichas=D.fichas.filter(x=>x!==f);L(q,'fichas','Ficha ELIMINADA',`${f.type}: ${f.name}`);saveAll();s.json({})});

// ---------- Informes ----------
app.get('/api/reports',auth(1),(q,s)=>s.json(D.reports.filter(r=>canR(r,q.u)).reverse().map(r=>({...r,url:undefined}))));
app.post('/api/reports',auth(1),(q,s)=>{const b=q.body;if(!/^https:\/\/(docs|drive)\.google\.com\//.test(b.url||''))return E(s,'Pega un enlace válido de Google Docs');
if(!b.context)return E(s,'Escribe el contexto del informe');const i=b.inv?D.invs.find(x=>x.id==b.inv):null;if(b.inv&&(!i||!(vis(i,q.u)||q.lv>=3)))return E(s,'Investigación no válida');
const r={id:++D.seq.r,url:b.url,inv:i?i.id:null,invName:i?i.name:'',context:String(b.context).slice(0,3000),by:q.u.id,byName:`${q.u.name} (${q.u.plate})`,ts:new Date().toISOString(),shared:[]};
D.reports.push(r);L(q,'informes','Informe enviado',`Nº ${r.id}${i?' · investigación '+i.name:''}`,r.inv);saveAll();s.json(r)});
app.post('/api/reports/:id/open',auth(),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r||!canR(r,q.u))return E(s,'No tienes acceso a este informe',403);
L(q,'informes','Informe abierto',`Nº ${r.id}${r.invName?' · '+r.invName:''}`,r.inv);s.json({url:r.url})});
app.put('/api/reports/:id/inv',auth(3),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id),i=q.body.inv?D.invs.find(x=>x.id==q.body.inv):null;if(!r)return E(s,'No existe',404);if(q.body.inv&&!i)return E(s,'Investigación no válida');
const old=r.invName||'ninguna';r.inv=i?i.id:null;r.invName=i?i.name:'';L(q,'informes','Informe asociado a investigación',`Nº ${r.id}: ${old} → ${r.invName||'ninguna'}${i?' (el equipo de la investigación ya puede verlo)':''}`,r.inv);saveAll();s.json({})});
app.post('/api/reports/:id/share',auth(3),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r)return E(s,'No existe',404);
r.shared=(q.body.users||[]).map(Number);L(q,'informes','Permisos de informe modificados',`Nº ${r.id} visible para: ${r.shared.map(nm).join(', ')||'nadie más'}`,r.inv);saveAll();s.json(r)});
app.delete('/api/reports/:id',auth(3),(q,s)=>{const r=D.reports.find(x=>x.id==q.params.id);if(!r)return E(s,'No existe',404);
D.reports=D.reports.filter(x=>x!==r);L(q,'informes','Informe ELIMINADO',`Nº ${r.id} de ${r.byName}`,r.inv);saveAll();s.json({})});

// ---------- Investigaciones ----------
const okStaff=id=>D.users.some(u=>u.id==id&&staff(u));
app.get('/api/inv',auth(),(q,s)=>s.json(D.invs.filter(i=>(q.query.all&&q.lv>=3)||vis(i,q.u)).map(i=>({id:i.id,name:i.name,desc:i.desc,st:i.st||'Abierta',pr:i.pr||'Media',lead:i.lead,team:i.team,leadName:nm(i.lead)}))));
app.post('/api/inv',auth(2),(q,s)=>{const b=q.body,lead=+b.lead;if(!b.name||!okStaff(lead))return E(s,'Indica nombre y mando a cargo');
const i={id:++D.seq.i,name:String(b.name).slice(0,100),desc:String(b.desc||'').slice(0,500),lead,team:[...new Set((b.team||[]).map(Number))].filter(x=>x!=lead&&okStaff(x)),info:[],people:[],st:'Abierta',pr:'Media',ts:new Date().toISOString()};
D.invs.push(i);L(q,'investigaciones','Investigación creada',`${i.name} · mando: ${nm(lead)} · investigadores: ${i.team.map(nm).join(', ')||'—'}`,i.id);saveAll();s.json({id:i.id})});
const gi=(q,s)=>{const i=D.invs.find(x=>x.id==q.params.id);if(!i||!vis(i,q.u)){E(s,'No existe o no tienes acceso',404);return null}return i};
app.get('/api/inv/:id',auth(),(q,s)=>{const i=gi(q,s);if(!i)return;s.json({...i,leadName:nm(i.lead),teamNames:i.team.map(id=>({id,name:nm(id)})),reports:D.reports.filter(r=>r.inv==i.id&&canR(r,q.u)).map(r=>({...r,url:undefined})),canManage:mg(i,q.u),canEdit:ed(i,q.u),canEditInfo:edI(i,q.u)})});
const W=(p,m,perm,fn)=>app[m]('/api/inv/:id'+p,auth(),(q,s)=>{const i=gi(q,s);if(!i)return;if(perm&&!perm(i,q.u))return E(s,'No tienes permisos para hacer esto',403);fn(q,s,i)});
const rid=()=>C.randomBytes(4).toString('hex');
W('/info','post',ed,(q,s,i)=>{const{k,v}=q.body;if(!k||!v)return E(s,'Completa ambos campos');i.info.push({id:rid(),k:String(k).slice(0,60),v:String(v).slice(0,500),by:q.u.name});L(q,'investigaciones','Dato añadido',`${i.name}: ${k} = ${v}`,i.id);saveAll();s.json({})});
W('/info/:x','put',edI,(q,s,i)=>{const d=i.info.find(x=>x.id==q.params.x),{k,v}=q.body;if(!d)return E(s,'No existe',404);if(!k||!v)return E(s,'Completa ambos campos');
L(q,'investigaciones','Dato EDITADO',`${i.name}: ${d.k} = ${d.v} → ${k} = ${v}`,i.id);d.k=String(k).slice(0,60);d.v=String(v).slice(0,500);saveAll();s.json({})});
W('/info/:x','delete',mg,(q,s,i)=>{const d=i.info.find(x=>x.id==q.params.x);i.info=i.info.filter(x=>x!==d);L(q,'investigaciones','Dato ELIMINADO',`${i.name}: ${d?d.k+' = '+d.v:q.params.x}`,i.id);saveAll();s.json({})});
const imgs=a=>(a||[]).filter(f=>/^data:image\/(jpeg|png|webp|gif);base64,/.test(f)).slice(0,6);
W('/people','post',ed,(q,s,i)=>{const b=q.body;if(!b.name)return E(s,'Indica el nombre');const files=imgs(b.files);i.people.push({id:rid(),name:String(b.name).slice(0,80),role:String(b.role||'').slice(0,60),notes:String(b.notes||'').slice(0,500),files,by:q.u.name});L(q,'investigaciones','Persona involucrada añadida',`${i.name}: ${b.name}${files.length?' · '+files.length+' foto(s)':''}`,i.id);saveAll();s.json({})});
W('/people/:x','put',ed,(q,s,i)=>{const d=i.people.find(x=>x.id==q.params.x),b=q.body;if(!d)return E(s,'No existe',404);if(!b.name)return E(s,'Indica el nombre');const ch=[];
for(const k of['name','role','notes']){const v=String(b[k]||'').slice(0,k=='name'?80:k=='role'?60:500);if(v!==(d[k]||'')){ch.push(`${k}: ${d[k]||'—'} → ${v||'—'}`);d[k]=v}}
const f=imgs(b.files);if(JSON.stringify(f)!==JSON.stringify(d.files||[])){ch.push(`fotos: ${(d.files||[]).length} → ${f.length}`);d.files=f}
L(q,'investigaciones','Persona involucrada EDITADA',`${i.name} · ${d.name}: ${ch.join(' | ')||'sin cambios'}`,i.id);saveAll();s.json({})});
W('/people/:x','delete',mg,(q,s,i)=>{const d=i.people.find(x=>x.id==q.params.x);i.people=i.people.filter(x=>x!==d);L(q,'investigaciones','Persona involucrada ELIMINADA',`${i.name}: ${d?d.name:q.params.x}`,i.id);saveAll();s.json({})});
W('/team','put',mg,(q,s,i)=>{const lead=+q.body.lead,ids=[...new Set((q.body.team||[]).map(Number))].filter(x=>x!=lead&&okStaff(x));if(!okStaff(lead))return E(s,'Mando no válido');
const add=ids.filter(x=>!i.team.includes(x)),rem=i.team.filter(x=>!ids.includes(x));
if(lead!=i.lead)L(q,'investigaciones','Cambio de mando a cargo',`${i.name}: ${nm(i.lead)} → ${nm(lead)}`,i.id);
add.forEach(x=>L(q,'investigaciones','Investigador añadido',`${i.name}: ${nm(x)}`,i.id));rem.forEach(x=>L(q,'investigaciones','Investigador retirado (pierde el acceso)',`${i.name}: ${nm(x)}`,i.id));
i.lead=lead;i.team=ids;saveAll();s.json({})});
W('','put',mg,(q,s,i)=>{const n=String(q.body.name||'').trim().slice(0,100),d=String(q.body.desc||'').trim().slice(0,500);if(!n)return E(s,'Indica el nombre de la investigación');const ch=[];
if(n!==i.name){ch.push(`nombre: ${i.name} → ${n}`);D.reports.forEach(r=>{if(r.inv==i.id)r.invName=n});i.name=n}if(d!==i.desc){ch.push('descripción modificada');i.desc=d}
const b=q.body;if(['Abierta','En espera','Cerrada'].includes(b.st)&&b.st!==(i.st||'Abierta')){ch.push(`estado: ${i.st||'Abierta'} → ${b.st}`);i.st=b.st}if(['Baja','Media','Alta'].includes(b.pr)&&b.pr!==(i.pr||'Media')){ch.push(`prioridad: ${i.pr||'Media'} → ${b.pr}`);i.pr=b.pr}
L(q,'investigaciones','Investigación editada',`${i.name}: ${ch.join(' | ')||'sin cambios'}`,i.id);saveAll();s.json({})});
W('','delete',mg,(q,s,i)=>{D.invs=D.invs.filter(x=>x!==i);D.users.forEach(u=>{u.inv=(u.inv||[]).filter(x=>x!=i.id)});L(q,'investigaciones','Investigación ELIMINADA',i.name,i.id);saveAll();s.json({})});


return { handle: (request) => app.handle(request) };
}
