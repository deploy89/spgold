import bcrypt from 'bcryptjs';

const COLLECTIONS = ['deposits','withdraws','trades','funds','chats','kycs'];
const rateMap = new Map();
function rateLimit(req, key, limit, windowMs){ const ip=req.headers.get('CF-Connecting-IP')||'unknown', k=key+':'+ip, n=Date.now(), old=rateMap.get(k); if(!old||n-old.start>windowMs){rateMap.set(k,{start:n,count:1});return true;} if(++old.count>limit)return false; return true; }
// Brute-force protection (v2): counts FAILED login attempts per account
// (phone/username), not per IP. 10 failures within 15min locks logins for that
// account until the window expires; a successful login resets the counter.
// Successful traffic therefore never blocks real users — only password
// guessing does. (In-memory per isolate: fine as a first-line defense.)
const failMap = new Map();
function failState(key,windowMs){const n=Date.now(),e=failMap.get(key);if(!e||n-e.start>windowMs)return {count:0,retryAfter:0};return {count:e.count,retryAfter:Math.max(1,Math.ceil((e.start+windowMs-n)/1000))};}
function recordFail(key,windowMs){const n=Date.now(),e=failMap.get(key);if(!e||n-e.start>windowMs)failMap.set(key,{start:n,count:1});else e.count++;}
function clearFails(key){failMap.delete(key);}
const LOGIN_FAIL_LIMIT=10, LOGIN_FAIL_WINDOW=15*60*1000;
// Guest chat anti-spam: 30 messages/hour per guest token (in-memory per isolate).
const guestMsgMap = new Map();
function guestMsgLimit(token){const n=Date.now(),e=guestMsgMap.get(token);if(!e||n-e.start>3600000){guestMsgMap.set(token,{start:n,count:1});return true;}if(++e.count>30)return false;return true;}
function tooManyLoginFails(key){const s=failState(key,LOGIN_FAIL_WINDOW);if(s.count<LOGIN_FAIL_LIMIT)return null;return json({ok:false,error:'พยายามเข้าสู่ระบบผิดพลาดหลายครั้งเกินไป กรุณารอประมาณ '+Math.ceil(s.retryAfter/60)+' นาทีแล้วลองใหม่อีกครั้ง'},429,{'Retry-After':String(s.retryAfter)});}
function secureResponse(resp){ const h=new Headers(resp.headers); h.set('X-Content-Type-Options','nosniff'); h.set('X-Frame-Options','DENY'); h.set('Referrer-Policy','strict-origin-when-cross-origin'); h.set('Permissions-Policy','camera=(), microphone=(), geolocation=()'); return new Response(resp.body,{status:resp.status,statusText:resp.statusText,headers:h}); }
const DEFAULT_SETTINGS = {
  siteName:'Binance Gold', site_name:'Binance Gold', welcomeText:'', welcome_text:'',
  aboutUs:'ยินดีต้อนรับสู่ Binance Gold', about_us:'ยินดีต้อนรับสู่ Binance Gold', withdrawFee:1, withdraw_fee:1, minWithdraw:10, min_withdraw:10,
  p2pAddress:'TLrt3947ScuuCguGRsKibuWvp9iZwmixXj', p2p_address:'TLrt3947ScuuCguGRsKibuWvp9iZwmixXj', p2pWithdrawFee:1, p2p_withdraw_fee:1,
  p2pMinWithdraw:10, p2p_min_withdraw:10, maintenance:false, autoTradeUserSettings:{},
  packages:'[{"percent":10,"amount":100},{"percent":30,"amount":1000},{"percent":40,"amount":2000},{"percent":60,"amount":4000},{"percent":70,"amount":6000},{"percent":80,"amount":10000}]',
  packages_json:'[{"percent":10,"amount":100},{"percent":30,"amount":1000},{"percent":40,"amount":2000},{"percent":60,"amount":4000},{"percent":70,"amount":6000},{"percent":80,"amount":10000}]',
  autoTradeEnabled:false,auto_trade_enabled:false,autoWinRate:50,auto_win_rate:50,autoTradeDelay:5,auto_trade_delay:5,autoTradeMode:'random',auto_trade_mode:'random'
};

const json = (data,status=200,headers={}) => new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','x-content-type-options':'nosniff','x-frame-options':'DENY','referrer-policy':'strict-origin-when-cross-origin',...headers}});
const now=()=>new Date().toISOString();
const parse=(s,f={})=>{try{return JSON.parse(s)}catch{return f}};
const strip=o=>{if(!o||typeof o!=='object')return o;const x={...o};delete x.password;delete x.password_hash;delete x.passwordHash;return x};
// member-facing user payload ต้องไม่มี note (บันทึกส่วนตัวของแอดมิน)
const safeUser=u=>{if(!u||typeof u!=='object')return u;const x={...u};delete x.note;return x};
// Member ID (user_code): ตัวเลข 5 หลัก (10000–99999) ไม่ซ้ำ เก็บใน data.user_code
async function genUserCode(env){for(let i=0;i<20;i++){const c=10000+Math.floor(Math.random()*90000);const x=await env.DB.prepare("SELECT 1 AS one FROM users WHERE json_extract(data,'$.user_code')=?").bind(c).first();if(!x)return c;}return 10000+Math.floor(Math.random()*90000);}
// Backfill สมาชิกเก่าที่ยังไม่มี user_code (เรียกครั้งเดียวต่อ isolate จาก ensureDefaults)
async function backfillUserCodes(env){const rs=await env.DB.prepare("SELECT id,data FROM users WHERE json_extract(data,'$.user_code') IS NULL LIMIT 500").all();for(const r of rs.results){if(parse(r.data,{}).user_code)continue;const c=await genUserCode(env);await env.DB.prepare("UPDATE users SET data=json_set(data,'$.user_code',?) WHERE id=? AND json_extract(data,'$.user_code') IS NULL").bind(c,r.id).run();}}
// เติม user_code ให้ rows ของ deposits/withdraws/trades/funds/kycs/chats (query users รวมครั้งเดียว)
async function attachUserCodes(env,rows){if(!rows||!rows.length)return rows;const ids=[...new Set(rows.map(r=>r.user_id||r.userId).filter(Boolean))];if(!ids.length)return rows;const rs=await env.DB.prepare(`SELECT id,json_extract(data,'$.user_code') c FROM users WHERE id IN (${ids.map(()=>'?').join(',')})`).bind(...ids).all();const map=Object.fromEntries(rs.results.map(x=>[x.id,x.c]));for(const r of rows){const uid=r.user_id||r.userId;if(uid&&r.user_code==null&&map[uid]!=null)r.user_code=map[uid];}return rows;}
const id=(p)=>p+crypto.randomUUID().replaceAll('-','').slice(0,20);
async function sha256(v){const b=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v));return [...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('')}
function cookie(name,value,maxAge=604800,secure=true){return `${name}=${value}; Path=/; HttpOnly;${secure?' Secure;':''} SameSite=Lax; Max-Age=${maxAge}`}
function cookieSecure(req){return new URL(req.url).protocol==='https:';}
function getCookies(req){return Object.fromEntries((req.headers.get('Cookie')||'').split(';').filter(Boolean).map(x=>{const i=x.indexOf('=');return [x.slice(0,i).trim(),decodeURIComponent(x.slice(i+1).trim())]}))}
function sessionCookieName(type){return type==='admin'?'bg_admin_sid':'bg_user_sid';}
function clearSessionCookies(req){
  const secure=cookieSecure(req);
  return [
    cookie(sessionCookieName('user'),' ',0,secure),
    cookie(sessionCookieName('admin'),' ',0,secure),
    cookie('bg_sid',' ',0,secure)
  ];
}
async function session(req,env,type){
  const c=getCookies(req);
  // New role-specific cookies allow a member and an Admin to stay signed in
  // simultaneously in the same browser. bg_sid is accepted only as a legacy
  // fallback for sessions created by older deployments.
  const token=c[sessionCookieName(type)] || c.bg_sid;
  if(!token)return null;
  const h=await sha256(token);
  const r=await env.DB.prepare('SELECT actor_type,actor_id,expires_at FROM sessions WHERE id_hash=?').bind(h).first();
  if(!r||r.actor_type!==type||new Date(r.expires_at)<=new Date())return null;
  return r;
}
async function requireSession(req,env,type){return await session(req,env,type)}
// Superadmin check: role อยู่ใน data JSON ('superadmin'). รองรับ legacy 'super'
// และกรณีแอดมินหลัก (username ตรง ADMIN_USERNAME) ที่ seed เก่าไม่ได้ใส่ role —
// มิฉะนั้นเช็คแบบ fail-closed จะล็อกแอดมินหลักออกจากการเพิ่มผู้ดูแลเอง
async function requireSuperAdmin(req,env){const s=await requireSession(req,env,'admin');if(!s)return null;const r=await env.DB.prepare('SELECT id,username,data FROM admins WHERE id=?').bind(s.actor_id).first();if(!r)return null;const d=parse(r.data,{});let role=d.role;if(!role&&r.username&&r.username===String(env.ADMIN_USERNAME||'').trim())role='superadmin';return (role==='superadmin'||role==='super')?s:null}
function sameOrigin(req){const o=req.headers.get('Origin');return !o||o===new URL(req.url).origin}
async function body(req){const b=await req.json().catch(()=>({}));return b&&typeof b==='object'&&!Array.isArray(b)?b:{} }
function badKeys(o){if(!o||typeof o!=='object')return false;for(const k of Object.keys(o)){if(['__proto__','constructor','prototype'].includes(k)||badKeys(o[k]))return true}return false}
function userFromRow(r){if(!r)return null;const d=parse(r.data,{});return strip({...d,id:r.id,phone:r.phone,createdAt:d.createdAt||r.created_at})}
async function getUser(env,uid){return userFromRow(await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(uid).first())}
async function getRecord(env,col,rid){const r=await env.DB.prepare(`SELECT * FROM ${col} WHERE id=?`).bind(rid).first();return r?strip({...parse(r.data,{}),id:r.id,user_id:r.user_id,created_at:r.created_at,createdAt:parse(r.data,{}).createdAt||r.created_at}):null}
async function listRecords(env,col,uid,limit=500){let rs=uid?await env.DB.prepare(`SELECT * FROM ${col} WHERE user_id=? ORDER BY created_at DESC LIMIT ?`).bind(uid,limit).all():await env.DB.prepare(`SELECT * FROM ${col} ORDER BY created_at DESC LIMIT ?`).bind(limit).all();return rs.results.map(r=>strip({...parse(r.data,{}),id:r.id,user_id:r.user_id,created_at:r.created_at,createdAt:parse(r.data,{}).createdAt||r.created_at}))}
async function audit(env,actor,action,target,detail,ip){await env.DB.prepare('INSERT INTO audit_log(actor,action,target,detail,ip,created_at) VALUES(?,?,?,?,?,?)').bind(actor,action,target,JSON.stringify(detail||{}),ip||null,now()).run()}
async function notify(env,type,target,title,message){await env.DB.prepare('INSERT INTO notifications(id,type,target,title,message,created_at) VALUES(?,?,?,?,?,?)').bind(id('N'),type,target,title,message,now()).run()}
async function balance(env,uid,delta,type,ref,detail){const lid=id('L'),t=now(),dlt=Number(delta);if(!Number.isFinite(dlt))throw Error('invalid amount');const upd=env.DB.prepare("UPDATE users SET data=json_set(data,'$.balance',COALESCE(CAST(json_extract(data,'$.balance') AS REAL),0)+?) WHERE id=? AND COALESCE(CAST(json_extract(data,'$.balance') AS REAL),0)+? >= 0").bind(dlt,uid,dlt);const led=env.DB.prepare("INSERT INTO transaction_ledger(id,user_id,type,amount,balance_before,balance_after,reference_id,detail,created_at) SELECT ?,id,?,?,0,0,?,?,? FROM users WHERE id=? AND changes()>0").bind(lid,type,dlt,ref||null,JSON.stringify(detail||{}),t,uid);const r=await env.DB.batch([upd,led]);if(!r[0].meta?.changes) {const exists=await env.DB.prepare('SELECT id FROM users WHERE id=?').bind(uid).first();if(!exists)throw Error('user not found');throw Error('insufficient balance');}const u=await getUser(env,uid);const after=Number(u.balance)||0;await env.DB.prepare('UPDATE transaction_ledger SET balance_after=?,balance_before=? WHERE id=?').bind(after,after-dlt,lid).run();return {user:u,ledgerId:lid}}
async function idem(req,env,op,fn){const k=req.headers.get('Idempotency-Key');if(k){const r=await env.DB.prepare('SELECT response FROM idempotency_keys WHERE key=?').bind(k).first();if(r)return parse(r.response,{})}const out=await fn();if(k)await env.DB.prepare('INSERT OR IGNORE INTO idempotency_keys(key,operation,response,created_at) VALUES(?,?,?,?)').bind(k,op,JSON.stringify(out),now()).run();return out}
async function ensureDefaults(env){const c=await env.DB.prepare('SELECT COUNT(*) n FROM settings').first();if(!c.n)await env.DB.batch(Object.entries(DEFAULT_SETTINGS).map(([k,v])=>env.DB.prepare('INSERT INTO settings(key,value) VALUES(?,?)').bind(k,JSON.stringify(v))));
  // One-time bootstrap/repair for the configured admin account. This fixes an
  // existing account with the wrong password without exposing plaintext credentials.
  const adminPassword = env.ADMIN_PASSWORD || env.ADMIN_SEED_PASSWORD;
  const adminUsername = String(env.ADMIN_USERNAME || '').trim();
  const boot = await env.DB.prepare("SELECT value FROM settings WHERE key='__admin_bootstrap_v2'").first();
  if(!boot && adminUsername && adminPassword){
    const a=await env.DB.prepare('SELECT * FROM admins WHERE username=?').bind(adminUsername).first();
    const h=await bcrypt.hash(String(adminPassword),10);
    if(!a){await env.DB.prepare('INSERT INTO admins(id,username,password_hash,data,created_at) VALUES(?,?,?,?,?)').bind(id('A'),adminUsername,h,JSON.stringify({name:'ผู้ดูแลระบบหลัก',role:'superadmin'}),now()).run();}
    else {await env.DB.prepare('UPDATE admins SET password_hash=?, data=? WHERE id=?').bind(h,JSON.stringify({...parse(a.data,{}),id:a.id,username:adminUsername,name:parse(a.data,{}).name||'ผู้ดูแลระบบหลัก',role:parse(a.data,{}).role||'superadmin'}),a.id).run();}
    await env.DB.prepare("INSERT OR REPLACE INTO settings(key,value) VALUES('__admin_bootstrap_v2',?)").bind(JSON.stringify({username:adminUsername,at:now()})).run();
  }
  // Heal the configured main admin's role on every isolate start (cheap UPDATE,
  // no-op when already correct): older seeds stored no role or role:'super',
  // which the fail-closed superadmin check rejected, breaking "add admin".
  if(adminUsername)await env.DB.prepare("UPDATE admins SET data=json_set(data,'$.role','superadmin') WHERE username=? AND COALESCE(json_extract(data,'$.role'),'')<>'superadmin'").bind(adminUsername).run();
  try{await backfillUserCodes(env);}catch(e){console.error('backfillUserCodes',e)}
}
async function login(env,type,identifier,password){
  let r=type==='user'
    ? await env.DB.prepare('SELECT * FROM users WHERE phone=?').bind(identifier).first()
    : await env.DB.prepare('SELECT * FROM admins WHERE username=?').bind(identifier).first();

  let valid = !!(r && r.password_hash && await bcrypt.compare(String(password), r.password_hash));

  // Repair/create the configured bootstrap Admin only when the submitted
  // credentials exactly match the server-side secret. This also repairs an
  // Admin whose password was changed previously, without storing plaintext.
  if(type==='admin' && !valid){
    const configuredUsername=String(env.ADMIN_USERNAME||'').trim();
    const configuredPassword=env.ADMIN_PASSWORD||env.ADMIN_SEED_PASSWORD||'';
    if(configuredUsername && configuredPassword && String(identifier).trim()===configuredUsername && String(password)===String(configuredPassword)){
      const existing=await env.DB.prepare('SELECT * FROM admins WHERE username=?').bind(configuredUsername).first();
      const h=await bcrypt.hash(String(configuredPassword),10);
      if(existing){
        const d=parse(existing.data,{});
        await env.DB.prepare('UPDATE admins SET password_hash=?, data=? WHERE id=?').bind(h,JSON.stringify({...d,id:existing.id,username:configuredUsername,name:d.name||'ผู้ดูแลระบบหลัก',role:d.role||'superadmin'}),existing.id).run();
      }else{
        const aid=id('A');
        await env.DB.prepare('INSERT INTO admins(id,username,password_hash,data,created_at) VALUES(?,?,?,?,?)').bind(aid,configuredUsername,h,JSON.stringify({id:aid,username:configuredUsername,name:'ผู้ดูแลระบบหลัก',role:'superadmin'}),now()).run();
      }
      r=await env.DB.prepare('SELECT * FROM admins WHERE username=?').bind(configuredUsername).first();
      valid=!!(r && r.password_hash && await bcrypt.compare(String(password),r.password_hash));
    }
  }

  if(!valid)return null;
  const raw=crypto.randomUUID()+crypto.randomUUID(),h=await sha256(raw),sid=r.id;
  // Session lifetime: members stay signed in 30 days (so reopening the browser
  // auto-logs them in); admins only 24h for security. The cookie Max-Age set by
  // the login routes must match this TTL.
  const ttlMs=type==='admin'?86400000:30*86400000;
  await env.DB.prepare('INSERT INTO sessions(id_hash,actor_type,actor_id,expires_at,created_at) VALUES(?,?,?,?,?)').bind(h,type,sid,new Date(Date.now()+ttlMs).toISOString(),now()).run();
  return {token:raw,user:type==='user'?userFromRow(r):strip({...parse(r.data,{}),id:r.id,username:r.username})};
}

// ensureDefaults runs once per isolate, not on every request (D1 is the source
// of truth; this only skips a redundant COUNT/bootstrap probe per request).
// Auto-settle: closes due trades/funds server-side even when nobody has a page
// open. Runs at most once per 10s per isolate (module-level throttle). If the
// admin already set a result it is honored; otherwise a result is drawn using
// the autoWinRate setting and stored on the record (autoSettled flag) so the
// admin can see what happened. Balance credit happens only after a conditional
// UPDATE confirms the record was still open, preventing double payout.
let lastAutoSettle=0;
// สุ่มยอดกำไร "ครั้งเดียวตอน settle" แล้วบันทึกลง record (field profit)
// สูตรใหม่: กำไร = base + 1 ถึง base + 5 (จำนวนเต็ม) เช่น base=10 → 11–15 เสมอ
function randomizeProfit(base){base=Number(base)||0;if(base<=0)return 0;return base+(1+Math.floor(Math.random()*5));}
// ยอดขาดทุน: ใช้กลไกสุ่มเดียวกันบน stake (base= stake ตามโมเดลเดิมที่เสียเต็ม stake)
// แต่ห้ามหักเกิน stake → ผลลัพธ์ไม่เกินยอดเดิมพันเสมอ
function randomizeLoss(stake){stake=Number(stake)||0;if(stake<=0)return 0;return Math.min(randomizeProfit(stake),stake)}
// กำไรกองทุน: คำนวณเป๊ะตามเปอร์เซ็นต์ (เงินต้น × pct/100, ปัด 2 ตำแหน่ง) — ไม่สุ่ม
function exactFundProfit(amount,pct){return Math.round((Number(amount)||0)*(Number(pct)||0)/100*100)/100;}
async function autoSettle(env){
  const t0=Date.now();
  if(t0-lastAutoSettle<10000)return;
  lastAutoSettle=t0;
  const iso=new Date().toISOString();
  let winRate=50;
  try{
    const rs=await env.DB.prepare("SELECT key,value FROM settings WHERE key IN ('autoWinRate','auto_win_rate')").all();
    for(const r of rs.results){const v=Number(parse(r.value,r.value));if(Number.isFinite(v))winRate=v}
  }catch(e){}
  if(!Number.isFinite(winRate)||winRate<0||winRate>100)winRate=50;
  const roll=()=>Math.random()*100<winRate?'win':'lose';
  try{
    const trades=await env.DB.prepare("SELECT id,user_id,data FROM trades WHERE json_extract(data,'$.status')='pending' AND json_extract(data,'$.endTime') IS NOT NULL AND json_extract(data,'$.endTime')<=? LIMIT 20").bind(iso).all();
    for(const row of trades.results){
      const t=parse(row.data,{}),amount=Number(t.amount)||0,pct=Number(t.percent||(t.package&&t.package.percent)||0);
      const hadResult=(t.result==='win'||t.result==='lose');
      const result=hadResult?t.result:roll();
      const profit=result==='win'?randomizeProfit(amount*pct/100):-randomizeLoss(amount);
      const x={...t,id:row.id,user_id:row.user_id,userId:row.user_id,result,resultSetAt:t.resultSetAt||iso,status:'closed',profit,closed_at:iso,autoSettled:!hadResult};
      const r=await env.DB.prepare("UPDATE trades SET data=? WHERE id=? AND json_extract(data,'$.status')='pending'").bind(JSON.stringify(x),row.id).run();
      if(!r.meta||!r.meta.changes)continue;
      if(result==='win')await balance(env,row.user_id,amount+profit,'trade_settlement',row.id,{result,auto:true});
    }
  }catch(e){console.error('autoSettle trades',e)}
  try{
    const funds=await env.DB.prepare("SELECT id,user_id,data FROM funds WHERE json_extract(data,'$.status')='active' AND json_extract(data,'$.endTime') IS NOT NULL AND json_extract(data,'$.endTime')<=? LIMIT 20").bind(iso).all();
    for(const row of funds.results){
      const f=parse(row.data,{}),amount=Number(f.amount)||0,pct=Number(f.percent)||0;
      const result='win';// กองทุน: กำไรเสมอ (ไม่มีผลแพ้)
      const profit=exactFundProfit(amount,pct);
      const x={...f,id:row.id,user_id:row.user_id,userId:row.user_id,result,resultSetAt:f.resultSetAt||iso,status:'completed',profit,settledAt:iso,autoSettled:true};
      const r=await env.DB.prepare("UPDATE funds SET data=? WHERE id=? AND json_extract(data,'$.status')='active'").bind(JSON.stringify(x),row.id).run();
      if(!r.meta||!r.meta.changes)continue;
      await balance(env,row.user_id,amount+profit,'fund_settlement',row.id,{result,auto:true});
    }
  }catch(e){console.error('autoSettle funds',e)}
}
let defaultsReady=false;
export default {async fetch(req,env,ctx){
  if(!defaultsReady){await ensureDefaults(env);defaultsReady=true;}
  if(ctx&&ctx.waitUntil)ctx.waitUntil(autoSettle(env).catch(e=>console.error(e)));
  const u=new URL(req.url); const path=u.pathname;
  const host = req.headers.get('host');
  if(host === 'https://bngold-v2.deploy825.workers.dev/admin.html' && (path === '/' || path === '/index.html')) {
    const r = new Request(new URL('/admin.html', u), req);
    const html = await resp.text();
    const out = html.includes('/api-db.js') ? html : (html.includes('</body>') ? html.replace('</body>', '<script src="/api-db.js"></script></body>') : html + '<script src="/api-db.js"></script>');
    return new Response(out, {status: resp.status, headers: {'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-cache'}});
  }
  if(path.startsWith('/api/')){
    // Root cause of the old "too many requests" lockouts: the auth bucket
    // (40 req/15min/IP) counted /api/auth/me + /api/auth/logout too — those fire
    // on every page load and on every sync, so a handful of page refreshes on a
    // shared 4G NAT IP exhausted the limit for everyone behind that IP.
    // v2: only credential-bearing endpoints (member login/register, admin login)
    // use the auth bucket, raised to 300/15min/IP; session checks and logout
    // count under the normal API bucket. Actual brute-force protection is
    // handled per account by failed-attempt counting (see tooManyLoginFails).
    const isAuth=/^\/api\/(auth\/(login|register)|admin\/login)$/.test(path);
    // Limits raised: previous 300/15min was exhausted in ~2-3 min by the admin
    // dashboard auto-refresh (10+ requests per cycle), causing site-wide 429s.
    // api bucket raised 1500→3000/15min for admin light-poll + chat poll + concurrent members.
    if(!rateLimit(req,isAuth?'auth':'api',isAuth?300:3000,15*60*1000)) return json({ok:false,error:'ระบบมีการใช้งานหนาแน่นเกินไป กรุณารอสักครู่แล้วลองใหม่อีกครั้ง (too many requests)'},429,{'Retry-After':'900'});
    if(!sameOrigin(req)&&req.method!=='GET')return json({ok:false,error:'origin rejected'},403);
    try{return await api(req,env,u);}catch(e){console.error(e);return json({ok:false,error:e.message||'internal error'},500)}
  }
  if(path==='/'||path==='/index.html'||path==='/admin'||path==='/admin.html'){const target=(path==='/admin'||path==='/admin.html')?'/admin.html':'/index.html';const r=new Request(new URL(target,u),req);const resp=await env.ASSETS.fetch(r);const html=await resp.text();const out=html.includes('/api-db.js')?html:(html.includes('</body>')?html.replace('</body>','<script src="/api-db.js"></script></body>'):html+'<script src="/api-db.js"></script>');return new Response(out,{status:resp.status,headers:{'content-type':'text/html; charset=utf-8','cache-control':'no-cache'}})}
  // Public media files uploaded to R2 via POST /api/media (admin). Keys are
  // random+immutable, so cache forever. No auth/rate-limit bucket on reads.
  if(path.startsWith('/media/')){
    if(!env.MEDIA)return json({ok:false,error:'not found'},404);
    const key=decodeURIComponent(path.slice(1));
    const obj=await env.MEDIA.get(key);
    if(!obj)return json({ok:false,error:'not found'},404);
    const h=new Headers();
    obj.writeHttpMetadata(h);
    if(!h.get('content-type'))h.set('content-type','application/octet-stream');
    h.set('cache-control','public, max-age=31536000, immutable');
    h.set('etag',obj.httpEtag);
    return new Response(obj.body,{headers:h});
  }
  return env.ASSETS.fetch(req);
}}

async function api(req,env,u){const p=u.pathname.replace(/^\/api\/?/,'').split('/').filter(Boolean);const method=req.method;
  if(p[0]==='health')return json({ok:true,environment:env.APP_ENV||'production'});
  if(p[0]==='auth'&&p[1]==='register'&&method==='POST'){const b=await body(req);if(badKeys(b)||!b.name||!b.phone||!b.password||String(b.password).length<4)return json({ok:false,error:'validation failed'},400);const phone=String(b.phone).trim();const ex=await env.DB.prepare('SELECT id FROM users WHERE phone=?').bind(phone).first();if(ex)return json({ok:false,error:'phone already registered'},409);const h=await bcrypt.hash(String(b.password),10),uid=phone,t=now(),uc=await genUserCode(env),data={id:uid,name:String(b.name).trim(),phone,user_code:uc,balance:0,vip:1,kycStatus:'none',avatar:null,createdAt:t};await env.DB.prepare('INSERT INTO users(id,phone,password_hash,data,created_at) VALUES(?,?,?,?,?)').bind(uid,phone,h,JSON.stringify(data),t).run();const l=await login(env,'user',phone,String(b.password));await notify(env,'register',uid,'สมาชิกใหม่',`${data.name} สมัครสมาชิก`);return json({ok:true,user:data},201,{'set-cookie':cookie(sessionCookieName('user'),l.token,2592000,cookieSecure(req))})}
  if(p[0]==='auth'&&p[1]==='login'&&method==='POST'){const b=await body(req);const phone=String(b.phone||'').trim();const fk='login:user:'+phone;const blocked=tooManyLoginFails(fk);if(blocked)return blocked;const l=await login(env,'user',phone,String(b.password||''));if(!l){recordFail(fk,LOGIN_FAIL_WINDOW);return json({ok:false,error:'invalid credentials'},401);}clearFails(fk);return json({ok:true,user:safeUser(l.user)},200,{'set-cookie':cookie(sessionCookieName('user'),l.token,2592000,cookieSecure(req))})}
  if(p[0]==='auth'&&p[1]==='me'&&method==='GET'){const s=await requireSession(req,env,'user');if(!s)return json({ok:false,error:'unauthorized'},401);const user=await getUser(env,s.actor_id);return user?json({ok:true,user:safeUser(user)}):json({ok:false,error:'unauthorized'},401)}
  if(p[0]==='auth'&&p[1]==='logout'&&method==='POST'){const c=getCookies(req);for(const name of [sessionCookieName('user'),'bg_sid']){if(c[name])await env.DB.prepare('DELETE FROM sessions WHERE id_hash=?').bind(await sha256(c[name])).run();}return new Response(JSON.stringify({ok:true}),{status:200,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','set-cookie':clearSessionCookies(req)}})}
  if(p[0]==='admin'&&p[1]==='login'&&method==='POST'){const b=await body(req);const uname=String(b.username||'').trim();const fk='login:admin:'+uname;const blocked=tooManyLoginFails(fk);if(blocked)return blocked;const l=await login(env,'admin',uname,String(b.password||''));if(!l){recordFail(fk,LOGIN_FAIL_WINDOW);return json({ok:false,error:'invalid credentials'},401);}clearFails(fk);await audit(env,'admin:'+l.user.id,'admin_login',l.user.username,{},req.headers.get('CF-Connecting-IP'));return json({ok:true,admin:l.user},200,{'set-cookie':cookie(sessionCookieName('admin'),l.token,86400,cookieSecure(req))})}
  if(p[0]==='admin'&&p[1]==='me'&&method==='GET'){const s=await requireSession(req,env,'admin');if(!s)return json({ok:false,error:'unauthorized'},401);const r=await env.DB.prepare('SELECT * FROM admins WHERE id=?').bind(s.actor_id).first();return r?json({ok:true,admin:strip({...parse(r.data,{}),id:r.id,username:r.username})}):json({ok:false,error:'unauthorized'},401)}
  if(p[0]==='admin'&&p[1]==='logout'&&method==='POST'){const c=getCookies(req);for(const name of [sessionCookieName('admin'),'bg_sid']){if(c[name])await env.DB.prepare('DELETE FROM sessions WHERE id_hash=?').bind(await sha256(c[name])).run();}return new Response(JSON.stringify({ok:true}),{status:200,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','set-cookie':clearSessionCookies(req)}})}
  if(p[0]==='settings'&&method==='GET'){const rs=await env.DB.prepare('SELECT key,value FROM settings').all();const o={};for(const r of rs.results){if(String(r.key).startsWith('__'))continue;o[r.key]=parse(r.value,r.value);}return json(o)}
  // ===== Guest support chat (ไม่ต้องล็อกอิน) =====
  // Thread เก็บในตาราง chats เดิม โดย user_id = 'guest:<token>' (token สุ่มที่
  // client เก็บใน localStorage) — แอดมินเห็น/ตอบผ่าน dashboard ปกติ และ guest
  // อ่าน/เขียนได้เฉพาะ thread ของ token ตัวเองเท่านั้น
  const GUEST_TOKEN_RE=/^[A-Za-z0-9]{20,80}$/;
  if(p[0]==='chat'&&p[1]==='guest'){
    if(method==='GET'){const tk=String(u.searchParams.get('token')||'');if(!GUEST_TOKEN_RE.test(tk))return json({ok:false,error:'invalid token'},400);let rows=await listRecords(env,'chats','guest:'+tk,500);const since=u.searchParams.get('since');if(since){const s=String(since);rows=rows.filter(r=>String(r.created_at||r.createdAt||'')>s)}return json({ok:true,messages:rows})}
    if(method==='POST'){const b=await body(req);if(badKeys(b))return json({ok:false,error:'invalid field name'},400);let tk=String(b.token||'');const fresh=!GUEST_TOKEN_RE.test(tk);if(fresh)tk=crypto.randomUUID().replaceAll('-','')+crypto.randomUUID().replaceAll('-','').slice(0,16);const msg=b.message==null?'':String(b.message);const type=b.type==='image'?'image':'text';
      if(!msg)return json({ok:true,token:tk,created:fresh}); // ขอ token ใหม่เฉยๆ
      if(!guestMsgLimit(tk))return json({ok:false,error:'ส่งข้อความถี่เกินไป กรุณารอสักครู่ (สูงสุด 30 ข้อความ/ชั่วโมง)'},429,{'Retry-After':'3600'});
      if(type==='image'&&!/^data:image\//.test(msg)&&!/^\/media\//.test(msg))return json({ok:false,error:'invalid image'},400);
      if(msg.length>2000000)return json({ok:false,error:'ไฟล์รูปใหญ่เกินไป'},413);
      const t=now(),rid=id('C'),guid='guest:'+tk,data=strip({id:rid,user_id:guid,userId:guid,sender:'user',guest:true,message:msg,type,createdAt:t,created_at:t});await env.DB.prepare('INSERT INTO chats(id,user_id,data,created_at) VALUES(?,?,?,?)').bind(rid,guid,JSON.stringify(data),t).run();return json({ok:true,token:tk,chat:data},201)}
    return json({ok:false,error:'method not allowed'},405);
  }
  const [user,admin]=await Promise.all([requireSession(req,env,'user'),requireSession(req,env,'admin')]);
  // POST /api/media (admin only): raw body + x-file-type header → R2 bucket.
  // รูปเล็กๆ ยังใช้ base64 ใน settings ได้เหมือนเดิม; endpoint นี้สำหรับไฟล์ใหญ่/วิดีโอ
  if(p[0]==='media'&&method==='POST'){
    if(!admin)return json({ok:false,error:'forbidden'},403);
    if(!env.MEDIA)return json({ok:false,error:'ยังไม่ได้เปิดใช้งานที่เก็บไฟล์ (ยังไม่ได้ผูก R2 bucket — รัน npx wrangler r2 bucket create bg-media แล้ว deploy ใหม่)'},503);
    const ct=String(req.headers.get('x-file-type')||'').split(';')[0].trim().toLowerCase();
    const okType=/^image\/[a-z0-9.+-]+$/.test(ct)||['video/mp4','video/webm','video/quicktime'].includes(ct);
    if(!okType)return json({ok:false,error:'รองรับเฉพาะไฟล์รูปภาพหรือวิดีโอ (mp4 / webm / mov)'},415);
    const MAX=80*1024*1024;
    const len=Number(req.headers.get('content-length')||0);
    if(len>MAX)return json({ok:false,error:'ไฟล์ใหญ่เกิน 80MB'},413);
    const buf=await req.arrayBuffer();
    if(!buf.byteLength)return json({ok:false,error:'ไฟล์ว่างเปล่า'},400);
    if(buf.byteLength>MAX)return json({ok:false,error:'ไฟล์ใหญ่เกิน 80MB'},413);
    const ext={'video/mp4':'.mp4','video/webm':'.webm','video/quicktime':'.mov','image/jpeg':'.jpg','image/png':'.png','image/gif':'.gif','image/webp':'.webp','image/svg+xml':'.svg','image/avif':'.avif'}[ct]||'';
    const key='media/'+Date.now().toString(36)+'-'+crypto.randomUUID().replaceAll('-','').slice(0,12)+ext;
    await env.MEDIA.put(key,buf,{httpMetadata:{contentType:ct}});
    await audit(env,'admin:'+admin.actor_id,'upload_media',key,{contentType:ct,size:buf.byteLength},req.headers.get('CF-Connecting-IP'));
    return json({ok:true,url:'/'+key,key:key,contentType:ct,size:buf.byteLength},201);
  }
  if(p[0]==='settings'&&method==='PUT'){if(!admin)return json({ok:false,error:'unauthorized'},401);const b=await body(req);await env.DB.batch(Object.entries(b).map(([k,v])=>env.DB.prepare('INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value').bind(k,JSON.stringify(v))));await audit(env,'admin:'+admin.actor_id,'update_settings','settings',{keys:Object.keys(b)},req.headers.get('CF-Connecting-IP'));const rs2=await env.DB.prepare('SELECT key,value FROM settings').all();const o2={};for(const r of rs2.results){if(String(r.key).startsWith('__'))continue;o2[r.key]=parse(r.value,r.value);}return json(o2)}
  if(p[0]==='users'&&method==='GET'){const q=String(u.searchParams.get('q')||'');const wantAll=u.searchParams.get('all')==='1';if(admin&&(wantAll||q)){const lim=Math.min(Number(u.searchParams.get('limit')||500),5000);let rs=q?await env.DB.prepare("SELECT * FROM users WHERE phone LIKE ? OR id LIKE ? OR json_extract(data,'$.name') LIKE ? ORDER BY created_at DESC LIMIT ?").bind('%'+q+'%','%'+q+'%','%'+q+'%',lim).all():await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC LIMIT ?').bind(lim).all();return json(rs.results.map(userFromRow))}if(user&&!q){const me=await getUser(env,user.actor_id);return me?json([safeUser(me)]):json([])}return json({ok:false,error:'forbidden'},403)}
  if(p[0]==='users'&&p.length===2&&method==='GET'){if(!admin&&(!user||user.actor_id!==p[1]))return json({ok:false,error:'forbidden'},403);const x=await getUser(env,p[1]);return x?json(admin?x:safeUser(x)):json({ok:false,error:'not found'},404)}
  if(p[0]==='users'&&p.length===2&&method==='PUT'){if(!admin&&(!user||user.actor_id!==p[1]))return json({ok:false,error:'forbidden'},403);const b=await body(req);if(Object.hasOwn(b,'balance')&&!admin)return json({ok:false,error:'balance transaction required'},403);if(!admin){const allow=['name','avatar','password','kycStatus'];const bad=Object.keys(b).filter(k=>!allow.includes(k));if(bad.length)return json({ok:false,error:'field not allowed',fields:bad},403);if(Object.hasOwn(b,'kycStatus')&&b.kycStatus!=='pending')return json({ok:false,error:'field not allowed',fields:['kycStatus']},403);}const r=await env.DB.prepare('SELECT * FROM users WHERE id=?').bind(p[1]).first();if(!r)return json({ok:false,error:'not found'},404);const d=parse(r.data,{});let delta=null;if(Object.hasOwn(b,'balance')){const nb=Number(b.balance);if(!Number.isFinite(nb))return json({ok:false,error:'invalid balance'},400);delta=nb-(Number(d.balance)||0);delete b.balance}let pwHash=null;if(Object.hasOwn(b,'password')){const pw=String(b.password||'');delete b.password;if(pw){if(pw.length<4)return json({ok:false,error:'password too short'},400);pwHash=await bcrypt.hash(pw,10);}}const nd={...d,...strip(b)};await env.DB.prepare('UPDATE users SET phone=?,data=?,password_hash=COALESCE(?,password_hash) WHERE id=?').bind(nd.phone||r.phone,JSON.stringify(nd),pwHash,p[1]).run();let out=await getUser(env,p[1]);if(delta)out=(await balance(env,p[1],delta,'admin_adjustment',null,{actor:admin?('admin:'+admin.actor_id):('user:'+p[1])})).user;return json(admin?out:safeUser(out))}
  if(p[0]==='users'&&p.length===2&&method==='DELETE'){if(!admin)return json({ok:false,error:'forbidden'},403);const target=p[1];const exists=await env.DB.prepare('SELECT id FROM users WHERE id=?').bind(target).first();if(!exists)return json({ok:false,error:'not found'},404);const del=COLLECTIONS.map(c=>env.DB.prepare(`DELETE FROM ${c} WHERE user_id=?`).bind(target));del.push(env.DB.prepare("DELETE FROM sessions WHERE actor_type='user' AND actor_id=?").bind(target));del.push(env.DB.prepare('DELETE FROM transaction_ledger WHERE user_id=?').bind(target));del.push(env.DB.prepare('DELETE FROM notifications WHERE target=?').bind(target));del.push(env.DB.prepare('DELETE FROM users WHERE id=?').bind(target));const dr=await env.DB.batch(del);await audit(env,'admin:'+admin.actor_id,'delete_user',target,{removed:dr.map(x=>(x&&x.meta&&x.meta.changes)||0)},req.headers.get('CF-Connecting-IP'));return json({ok:true,id:target})}
  if(p[0]==='transactions'&&method==='GET'){if(!user&&!admin)return json({ok:false,error:'unauthorized'},401);let uid;if(admin&&u.searchParams.get('all')==='1')uid=null;else if(admin&&u.searchParams.get('user_id'))uid=String(u.searchParams.get('user_id'));else if(user)uid=user.actor_id;else return json([]);return uid===null?json((await env.DB.prepare('SELECT * FROM transaction_ledger ORDER BY created_at DESC LIMIT 500').all()).results):json((await env.DB.prepare('SELECT * FROM transaction_ledger WHERE user_id=? ORDER BY created_at DESC LIMIT 500').bind(uid).all()).results)}
  if(p[0]==='notifications'&&method==='GET'){if(!admin)return json({ok:false,error:'forbidden'},403);return json((await env.DB.prepare('SELECT * FROM notifications ORDER BY created_at DESC LIMIT 200').all()).results)}
  if(p[0]==='wallet'&&p[1]==='withdraw'&&method==='POST'){if(!user)return json({ok:false,error:'unauthorized'},401);const b=await body(req),amount=Number(b.amount),fee=Number(b.fee||1);if(!Number.isFinite(amount)||amount<=0)return json({ok:false,error:'invalid amount'},400);const rec={...b,amount,status:'pending',reservedAmount:amount+fee,user_id:user.actor_id,userId:user.actor_id,createdAt:b.createdAt||now(),created_at:b.created_at||now()};const out=await idem(req,env,'wallet_withdraw',async()=>{const rid=String(rec.id||id('W'));delete rec.fee;await env.DB.prepare('INSERT INTO withdraws(id,user_id,data,created_at) VALUES(?,?,?,?)').bind(rid,user.actor_id,JSON.stringify({...rec,id:rid}),rec.created_at).run();const bal=await balance(env,user.actor_id,-amount-fee,'withdraw_reserve',rid,{amount,fee});await notify(env,'withdraw',user.actor_id,'รายการถอนเงินใหม่',`ถอน ${amount} USDT`);return {ok:true,withdraw:{...rec,id:rid},user:bal.user}});return json(out,201)}
  if(p[0]==='wallet'&&p[1]==='trade'&&method==='POST'){if(!user)return json({ok:false,error:'unauthorized'},401);const b=await body(req),amount=Number(b.amount);if(!Number.isFinite(amount)||amount<=0)return json({ok:false,error:'invalid amount'},400);const out=await idem(req,env,'wallet_trade',async()=>{const rid=String(b.id||id('T')),t={...b,id:rid,user_id:user.actor_id,userId:user.actor_id,status:b.status||'pending',createdAt:b.createdAt||now(),created_at:b.created_at||now()};const all=await env.DB.prepare('SELECT value FROM settings WHERE key=?').bind('autoTradeUserSettings').first();const ats=parse(all?.value,{}),us=ats[user.actor_id];if(us?.result){t.result=us.result==='random'?(Math.random()*100<(Number(us.winRate)||50)?'win':'lose'):us.result;t.resultSetAt=now()}await env.DB.prepare('INSERT INTO trades(id,user_id,data,created_at) VALUES(?,?,?,?)').bind(rid,user.actor_id,JSON.stringify(t),t.created_at).run();const bal=await balance(env,user.actor_id,-amount,'trade_open',rid,{symbol:t.symbol,type:t.type});await notify(env,'trade',user.actor_id,'รายการซื้อขายใหม่',`${t.symbol||''} ${amount} USDT`);return {ok:true,trade:t,user:bal.user}});return json(out,201)}
  if(p[0]==='wallet'&&p[1]==='trades'&&p[3]==='settle'&&method==='POST'){if(!user)return json({ok:false,error:'unauthorized'},401);const t=await getRecord(env,'trades',p[2]);if(!t)return json({ok:false,error:'not found'},404);if(t.user_id!==user.actor_id)return json({ok:false,error:'forbidden'},403);if(t.status==='closed')return json({ok:true,trade:t,user:safeUser(await getUser(env,user.actor_id))});if(!t.endTime||new Date(t.endTime)>new Date())return json({ok:false,error:'trade not due'},409);let result=t.result;let autoSettled=false;if(result!=='win'&&result!=='lose'){let winRate=50;try{const wr=await env.DB.prepare("SELECT value FROM settings WHERE key='autoWinRate'").first();const wv=Number(parse(wr?.value,wr?.value));if(Number.isFinite(wv)&&wv>=0&&wv<=100)winRate=wv}catch(e){}result=Math.random()*100<winRate?'win':'lose';autoSettled=true}const amount=Number(t.amount)||0,pct=Number(t.percent||(t.package&&t.package.percent)||0),profit=result==='win'?randomizeProfit(amount*pct/100):-randomizeLoss(amount);const r=await env.DB.prepare("UPDATE trades SET data=? WHERE id=? AND json_extract(data,'$.status')='pending'").bind(JSON.stringify({...t,result,resultSetAt:t.resultSetAt||now(),status:'closed',profit,closed_at:now(),autoSettled}),t.id).run();if(!r.meta||!r.meta.changes){const cur=await getRecord(env,'trades',p[2]);return json({ok:true,trade:cur||t,user:safeUser(await getUser(env,user.actor_id))});}const u=result==='win'?(await balance(env,user.actor_id,amount+profit,'trade_settlement',t.id,{result,auto:autoSettled})).user:await getUser(env,user.actor_id);return json({ok:true,trade:{...t,result,status:'closed',profit},user:safeUser(u)})}
  if(p[0]==='wallet'&&p[1]==='funds'&&p[3]==='settle'&&method==='POST'){if(!user)return json({ok:false,error:'unauthorized'},401);const f=await getRecord(env,'funds',p[2]);if(!f)return json({ok:false,error:'not found'},404);if(f.user_id!==user.actor_id)return json({ok:false,error:'forbidden'},403);if(f.status==='completed')return json({ok:true,fund:f,user:safeUser(await getUser(env,user.actor_id))});if(!f.endTime||new Date(f.endTime)>new Date())return json({ok:false,error:'fund not due'},409);const amount=Number(f.amount)||0,profit=exactFundProfit(amount,f.percent),x={...f,result:'win',resultSetAt:f.resultSetAt||now(),status:'completed',profit,settledAt:now(),autoSettled:true};const fr=await env.DB.prepare("UPDATE funds SET data=? WHERE id=? AND json_extract(data,'$.status')='active'").bind(JSON.stringify(x),f.id).run();if(!fr.meta||!fr.meta.changes){const cur=await getRecord(env,'funds',p[2]);return json({ok:true,fund:cur||f,user:safeUser(await getUser(env,f.user_id))});}const usr=(await balance(env,f.user_id,amount+profit,'fund_settlement',f.id,{result:'win',auto:true})).user;return json({ok:true,fund:x,user:safeUser(usr)})}
  if(p[0]==='wallet'&&p[1]==='fund'&&method==='POST'){if(!user)return json({ok:false,error:'unauthorized'},401);const b=await body(req),amount=Number(b.amount);if(!Number.isFinite(amount)||amount<=0)return json({ok:false,error:'invalid amount'},400);const out=await idem(req,env,'wallet_fund',async()=>{const rid=String(b.id||id('F')),t={...b,id:rid,user_id:user.actor_id,userId:user.actor_id,status:'active',createdAt:b.createdAt||now(),created_at:b.created_at||now()};await env.DB.prepare('INSERT INTO funds(id,user_id,data,created_at) VALUES(?,?,?,?)').bind(rid,user.actor_id,JSON.stringify(t),t.created_at).run();const bal=await balance(env,user.actor_id,-amount,'fund_open',rid,{days:t.days,percent:t.percent});return {ok:true,fund:t,user:bal.user}});return json(out,201)}
  if(p[0]==='admin'&&p[1]==='deposits'&&p[3]==='approve'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const d=await getRecord(env,'deposits',p[2]);if(!d)return json({ok:false,error:'not found'},404);if(d.status==='approved')return json({ok:true,deposit:d,user:await getUser(env,d.user_id)});if(d.status!=='pending')return json({ok:false,error:'already processed'},409);await env.DB.prepare('UPDATE deposits SET data=? WHERE id=?').bind(JSON.stringify({...d,status:'approved',approvedAt:now()}),d.id).run();const bal=await balance(env,d.user_id,Number(d.amount)||0,'deposit',d.id,{type:d.type||'deposit'});await audit(env,'admin:'+admin.actor_id,'approve_deposit',d.id,{},req.headers.get('CF-Connecting-IP'));return json({ok:true,deposit:{...d,status:'approved'},user:bal.user})}
  if(p[0]==='admin'&&p[1]==='deposits'&&p[3]==='reject'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const d=await getRecord(env,'deposits',p[2]);if(!d)return json({ok:false,error:'not found'},404);if(d.status!=='pending')return json({ok:true,deposit:d});const x={...d,status:'rejected',rejectedAt:now()};await env.DB.prepare('UPDATE deposits SET data=? WHERE id=?').bind(JSON.stringify(x),d.id).run();await audit(env,'admin:'+admin.actor_id,'reject_deposit',d.id,{},req.headers.get('CF-Connecting-IP'));return json({ok:true,deposit:x})}
  if(p[0]==='admin'&&p[1]==='withdraws'&&p[3]==='approve'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const w=await getRecord(env,'withdraws',p[2]);if(!w)return json({ok:false,error:'not found'},404);if(w.status!=='pending')return json({ok:true,withdraw:w});const x={...w,status:'approved',approvedAt:now()};await env.DB.prepare('UPDATE withdraws SET data=? WHERE id=?').bind(JSON.stringify(x),w.id).run();await audit(env,'admin:'+admin.actor_id,'approve_withdraw',w.id,{},req.headers.get('CF-Connecting-IP'));return json({ok:true,withdraw:x})}
  if(p[0]==='admin'&&p[1]==='withdraws'&&p[3]==='reject'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const w=await getRecord(env,'withdraws',p[2]);if(!w)return json({ok:false,error:'not found'},404);if(w.status==='approved')return json({ok:false,error:'cannot reject approved'},409);if(w.status==='rejected')return json({ok:true,withdraw:w});const x={...w,status:'rejected',rejectedAt:now()};await env.DB.prepare('UPDATE withdraws SET data=? WHERE id=?').bind(JSON.stringify(x),w.id).run();const bal=await balance(env,w.user_id,Number(w.reservedAmount||(Number(w.amount)||0)+1),'withdraw_refund',w.id,{});await audit(env,'admin:'+admin.actor_id,'reject_withdraw',w.id,{},req.headers.get('CF-Connecting-IP'));return json({ok:true,withdraw:x,user:bal.user})}
  if(p[0]==='admin'&&p[1]==='trades'&&p[3]==='settle'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const t=await getRecord(env,'trades',p[2]);if(!t)return json({ok:false,error:'not found'},404);if(t.status==='closed')return json({ok:true,trade:t});const b=await body(req),result=b.result==='win'?'win':'lose',amount=Number(t.amount)||0,profit=result==='win'?randomizeProfit(amount*(Number(t.percent||(t.package&&t.package.percent)||0))/100):-randomizeLoss(amount);const x={...t,status:'closed',profit,closed_at:now()};const r=await env.DB.prepare("UPDATE trades SET data=? WHERE id=? AND json_extract(data,'$.status')='pending'").bind(JSON.stringify(x),t.id).run();if(!r.meta||!r.meta.changes){const cur=await getRecord(env,'trades',p[2]);return json({ok:true,trade:cur||t,user:await getUser(env,t.user_id)});}const usr=result==='win'?(await balance(env,t.user_id,amount+profit,'trade_settlement',t.id,{result})).user:await getUser(env,t.user_id);await audit(env,'admin:'+admin.actor_id,'settle_trade',t.id,{result},req.headers.get('CF-Connecting-IP'));return json({ok:true,trade:x,user:usr})}
  if(p[0]==='admin'&&p[1]==='trades'&&p[3]==='preset'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const t=await getRecord(env,'trades',p[2]);if(!t)return json({ok:false,error:'not found'},404);const b=await body(req),result=b.result==='win'?'win':'lose';const x={...t,result,resultSetAt:now()};await env.DB.prepare('UPDATE trades SET data=? WHERE id=?').bind(JSON.stringify(x),t.id).run();await audit(env,'admin:'+admin.actor_id,'preset_trade',t.id,{result},req.headers.get('CF-Connecting-IP'));return json({ok:true,trade:x})}
  if(p[0]==='admin'&&p[1]==='funds'&&p[3]==='set-result'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const f=await getRecord(env,'funds',p[2]);if(!f)return json({ok:false,error:'not found'},404);await body(req);const x={...f,result:'win',resultSetAt:now()};await env.DB.prepare('UPDATE funds SET data=? WHERE id=?').bind(JSON.stringify(x),f.id).run();await audit(env,'admin:'+admin.actor_id,'set_fund_result',f.id,{result:'win'},req.headers.get('CF-Connecting-IP'));return json({ok:true,fund:x})}
  if(p[0]==='admin'&&p[1]==='funds'&&p[3]==='settle'&&method==='POST'){if(!admin)return json({ok:false,error:'forbidden'},403);const f=await getRecord(env,'funds',p[2]);if(!f)return json({ok:false,error:'not found'},404);if(f.status==='completed')return json({ok:true,fund:f});if(!f.endTime||new Date(f.endTime)>new Date())return json({ok:false,error:'fund not due'},409);const amount=Number(f.amount)||0,profit=exactFundProfit(amount,f.percent),x={...f,result:'win',resultSetAt:f.resultSetAt||now(),status:'completed',profit,settledAt:now()};const fr=await env.DB.prepare("UPDATE funds SET data=? WHERE id=? AND json_extract(data,'$.status')='active'").bind(JSON.stringify(x),f.id).run();if(!fr.meta||!fr.meta.changes){const cur=await getRecord(env,'funds',p[2]);return json({ok:true,fund:cur||f,user:await getUser(env,f.user_id)});}const usr=(await balance(env,f.user_id,amount+profit,'fund_settlement',f.id,{result:'win'})).user;return json({ok:true,fund:x,user:safeUser(usr)})}
  if(COLLECTIONS.includes(p[0])){if(!user&&!admin)return json({ok:false,error:'unauthorized'},401);const col=p[0];if(method==='GET'){
    // Member data is ALWAYS scoped to the session user. An admin sees the full
    // table only via the explicit ?all=1 flag (sent by the admin dashboard), or a
    // single user's rows via ?user_id=. A member page on a browser that also has
    // an admin cookie therefore can never receive other users' records.
    let uid;
    if(admin&&u.searchParams.get('all')==='1')uid=null;
    else if(admin&&u.searchParams.get('user_id'))uid=String(u.searchParams.get('user_id'));
    else if(user)uid=user.actor_id;
    else return json({ok:false,error:'forbidden'},403);
    let rows=await listRecords(env,col,uid,5000);
    rows=await attachUserCodes(env,rows);
    // Incremental polling support: ?since=<ISO timestamp> returns only rows
    // created after that point (ISO strings compare lexicographically). Used by
    // the chat UIs to poll a single thread every few seconds without
    // re-downloading the whole history (and its embedded images).
    const since=u.searchParams.get('since')||u.searchParams.get('after');
    if(since){const s=String(since);rows=rows.filter(r=>String(r.created_at||r.createdAt||'')>s)}
    return json(rows)}if(method==='POST'){const b=await body(req);if(badKeys(b))return json({ok:false,error:'invalid field name'},400);
    // Never trust a member-supplied user_id: member writes are bound to the
    // session user. Only an admin may create a record for another user, and only
    // by explicitly passing user_id/userId that differs from their own member id.
    const bid=String(b.user_id||b.userId||'');
    let uid;
    if(user&&(!admin||!bid||bid===user.actor_id))uid=user.actor_id;
    else if(admin&&bid)uid=bid;
    else if(user)uid=user.actor_id;
    else uid=null;
    if(!uid)return json({ok:false,error:'user required'},400);const rid=String(b.id||id(col.slice(0,1).toUpperCase())),t=b.created_at||b.createdAt||now(),data=strip({...b,id:rid,user_id:uid,userId:uid,createdAt:t,created_at:t});await env.DB.prepare(`INSERT INTO ${col}(id,user_id,data,created_at) VALUES(?,?,?,?)`).bind(rid,uid,JSON.stringify(data),t).run();if(['deposits','withdraws','kycs'].includes(col))await notify(env,col,uid,'รายการใหม่',`${col}: ${rid}`);return json(data,201)}if(p.length===2&&method==='GET'){const r=await getRecord(env,col,p[1]);if(!r)return json({ok:false,error:'not found'},404);if(!admin&&r.user_id!==user.actor_id)return json({ok:false,error:'forbidden'},403);return json(r)}if(p.length===2&&method==='PUT'){const r=await getRecord(env,col,p[1]);if(!r)return json({ok:false,error:'not found'},404);if(!admin&&r.user_id!==user.actor_id)return json({ok:false,error:'forbidden'},403);const b=await body(req);if(badKeys(b))return json({ok:false,error:'invalid field name'},400);if(!admin){const ALLOWED={deposits:['slip_url','slipUrl','note'],withdraws:['bank_info','bankInfo','address','note'],trades:[],funds:[],chats:['message','type'],kycs:['fullName','idNumber','dob','front_image_url','frontImageUrl','back_image_url','backImageUrl','selfie_image_url','selfieImageUrl']};const allow=ALLOWED[col]||[];const bad=Object.keys(b).filter(k=>!allow.includes(k));if(bad.length)return json({ok:false,error:'field not allowed',fields:bad},403);}const x=strip({...r,...b,id:r.id,user_id:r.user_id,userId:r.user_id});await env.DB.prepare(`UPDATE ${col} SET data=? WHERE id=?`).bind(JSON.stringify(x),r.id).run();if(admin)await audit(env,'admin:'+admin.actor_id,'edit_'+col,r.id,{fields:Object.keys(b)},req.headers.get('CF-Connecting-IP'));return json(x)}}
  if(p[0]==='admin'&&p[1]==='chats'&&method==='DELETE'){if(!admin)return json({ok:false,error:'forbidden'},403);const uid=String(u.searchParams.get('user_id')||'');if(!uid)return json({ok:false,error:'user_id required'},400);const r=await env.DB.prepare('DELETE FROM chats WHERE user_id=?').bind(uid).run();await audit(env,'admin:'+admin.actor_id,'delete_chats',uid,{},req.headers.get('CF-Connecting-IP'));return json({ok:true,deleted:r.meta?.changes||0})}
  if(p[0]==='admins'&&method==='GET'){if(!await requireSuperAdmin(req,env))return json({ok:false,error:'เฉพาะผู้ดูแลระบบหลัก (superadmin) เท่านั้น'},403);const rs=await env.DB.prepare('SELECT * FROM admins ORDER BY created_at ASC').all();return json(rs.results.map(r=>strip({...parse(r.data,{}),id:r.id,username:r.username,created_at:r.created_at,createdAt:parse(r.data,{}).createdAt||r.created_at})))}
  if(p[0]==='admins'&&method==='POST'){if(!await requireSuperAdmin(req,env))return json({ok:false,error:'เฉพาะผู้ดูแลระบบหลัก (superadmin) เท่านั้นที่เพิ่มผู้ดูแลได้'},403);const __ac=await env.DB.prepare('SELECT COUNT(*) n FROM admins').first();if((__ac&&__ac.n||0)>=10)return json({ok:false,error:'เพิ่มผู้ดูแลระบบได้สูงสุด 10 คน'},403);const b=await body(req);if(!b.username||!b.password||String(b.password).length<4)return json({ok:false,error:'กรุณากรอกชื่อผู้ใช้และรหัสผ่าน (อย่างน้อย 4 ตัวอักษร)'},400);const uname=String(b.username).trim();const dup=await env.DB.prepare('SELECT id FROM admins WHERE username=?').bind(uname).first();if(dup)return json({ok:false,error:'ชื่อผู้ใช้นี้ถูกใช้แล้ว'},409);const h=await bcrypt.hash(String(b.password),10),rid=id('A'),t=now(),data={id:rid,username:uname,name:b.name||'',role:b.role==='superadmin'?'admin':(b.role||'admin'),permissions:Array.isArray(b.permissions)&&b.permissions.length?b.permissions:['dashboard','users','deposits','withdraws','trades','fund','kyc','chat'],createdAt:t,created_at:t};try{await env.DB.prepare('INSERT INTO admins(id,username,password_hash,data,created_at) VALUES(?,?,?,?,?)').bind(rid,data.username,h,JSON.stringify(data),t).run();await audit(env,'admin:'+admin.actor_id,'create_admin',rid,{username:data.username},req.headers.get('CF-Connecting-IP'));return json({ok:true,...strip(data)},201)}catch(e){return json({ok:false,error:'ชื่อผู้ใช้นี้ถูกใช้แล้ว'},409)}}
  if(p[0]==='admins'&&p.length===2&&method==='DELETE'){if(!await requireSuperAdmin(req,env))return json({ok:false,error:'เฉพาะผู้ดูแลระบบหลัก (superadmin) เท่านั้น'},403);if(p[1]===admin.actor_id)return json({ok:false,error:'ไม่สามารถลบบัญชีตัวเองได้'},400);await env.DB.prepare('DELETE FROM admins WHERE id=?').bind(p[1]).run();await audit(env,'admin:'+admin.actor_id,'delete_admin',p[1],{},req.headers.get('CF-Connecting-IP'));return json({ok:true})}
  if(p[0]==='audit-log'&&method==='GET'){if(!admin)return json({ok:false,error:'forbidden'},403);return json((await env.DB.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all()).results)}
  return json({ok:false,error:'not found'},404);
}
