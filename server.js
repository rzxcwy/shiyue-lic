/**
 * 拾玥越狱 · 授权服务（Node 版，零依赖，Zeabur / Railway 通用）
 *
 * 环境变量：
 *   LIC_PRIVATE_KEY   lic_priv.pem 全文（BEGIN/END 保留）
 *   RESEND_API_KEY    re_xxx
 *   MAIL_FROM         拾玥越狱 <no-reply@你的域名>
 *   MAX_DEVICES       2
 *   DATA_DIR          /data（Zeabur 挂载卷的路径，没有就 ./）
 *   PORT              自动注入
 */
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 8080;
const DATA = path.join(process.env.DATA_DIR || '.', process.env.DATA_FILE || 'db.json');

let db = { users: {}, codes: {}, devices: {} };
function load() {
  try { db = JSON.parse(fs.readFileSync(DATA, 'utf8')); } catch (e) { /* 首次运行 */ }
}
function save() {
  try {
    fs.mkdirSync(path.dirname(DATA), { recursive: true });
    fs.writeFileSync(DATA, JSON.stringify(db));
  } catch (e) { console.error('保存失败', e.message); }
}
load();

const b64 = (b) => Buffer.from(b).toString('base64');
const hmac = (text, key) => b64(crypto.createHmac('sha256', String(key)).update(String(text)).digest());
const pbkdf2 = (pw, saltB64) =>
  new Promise((res, rej) =>
    crypto.pbkdf2(pw, Buffer.from(saltB64, 'base64'), 120000, 32, 'sha256',
      (e, d) => e ? rej(e) : res(b64(d))));

function sign(payload) {
  const key = process.env.LIC_PRIVATE_KEY || '';
  const sig = crypto.sign('sha256', Buffer.from(payload, 'utf8'),
    crypto.createPrivateKey(key));
  return b64(sig);
}
function issue(fp, email) {
  const exp = Date.now() + 30 * 24 * 3600 * 1000;
  const payload = ['v1', fp, email, String(exp), crypto.randomUUID()].join('|');
  return payload + '.' + sign(payload);
}

async function sendMail(email, code) {
  const r = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + process.env.RESEND_API_KEY, 'content-type': 'application/json' },
    body: JSON.stringify({
      from: process.env.MAIL_FROM,
      to: [email],
      subject: '拾玥越狱 注册验证码',
      text: `你的验证码是 ${code}，10 分钟内有效。\n如果不是本人操作，请忽略本邮件。`,
    }),
  });
  return r.ok;
}

function bindDevice(email, fp) {
  const d = db.devices[fp];
  if (d) return d.email === email ? { ok: true } : { ok: false, err: 'bound_other' };
  const cnt = Object.values(db.devices).filter(x => x.email === email && x.status === 'active').length;
  const max = parseInt(process.env.MAX_DEVICES || '2', 10);
  if (cnt >= max) return { ok: false, err: 'device_limit' };
  db.devices[fp] = { email, lic: crypto.randomUUID(), status: 'active', created: Date.now(), seen: Date.now() };
  save();
  return { ok: true };
}

function checkCode(email, code) {
  const c = db.codes[email];
  if (!c) return { ok: false, err: 'no_code' };
  const now = Date.now();
  if (now > c.exp) return { ok: false, err: 'expired' };
  if (c.attempts >= 5) return { ok: false, err: 'too_many' };
  const h = hmac(code, (process.env.MAIL_FROM || '') + email);
  if (h !== c.hash) { c.attempts++; save(); return { ok: false, err: 'bad_code' }; }
  return { ok: true };
}

const send = (res, code, obj) => {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'content-type': 'application/json',
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type',
    'access-control-allow-methods': 'POST,GET,OPTIONS',
  });
  res.end(body);
};

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  if (req.method === 'OPTIONS') return send(res, 204, {});
  if (url.pathname === '/ping')
    return send(res, 200, { ok: true, service: 'shiyue-lic', runtime: 'node', time: Date.now() });
  if (req.method !== 'POST') return send(res, 405, { ok: false, err: 'method' });

  let body = '';
  req.on('data', c => body += c);
  req.on('end', async () => {
    let j = {};
    try { j = JSON.parse(body || '{}'); } catch (e) { return send(res, 400, { ok: false, err: 'json' }); }
    const { email, password, code, device_fp, license } = j;
    try {
      if (url.pathname === '/request_code') {
        if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return send(res, 400, { ok: false, err: 'email' });
        const old = db.codes[email];
        if (old && Date.now() - old.sent < 60000) return send(res, 429, { ok: false, err: 'too_fast' });
        const c = String(Math.floor(100000 + Math.random() * 900000));
        db.codes[email] = { hash: hmac(c, (process.env.MAIL_FROM || '') + email), exp: Date.now() + 600000, attempts: 0, sent: Date.now() };
        save();
        if (!await sendMail(email, c)) return send(res, 502, { ok: false, err: 'mail' });
        return send(res, 200, { ok: true });
      }
      if (url.pathname === '/register') {
        if (!email || !password || !code || !device_fp) return send(res, 400, { ok: false, err: 'params' });
        if (password.length < 6) return send(res, 400, { ok: false, err: 'weak_password' });
        if (db.users[email]) return send(res, 409, { ok: false, err: 'exists' });
        const chk = checkCode(email, code);
        if (!chk.ok) return send(res, 400, { ok: false, err: chk.err });
        const salt = b64(crypto.randomBytes(16));
        db.users[email] = { pw: await pbkdf2(password, salt), salt, created: Date.now() };
        save();
        const b = bindDevice(email, device_fp);
        if (!b.ok) return send(res, 409, { ok: false, err: b.err });
        delete db.codes[email]; save();
        return send(res, 200, { ok: true, license: issue(device_fp, email) });
      }
      if (url.pathname === '/login_password') {
        if (!email || !password || !device_fp) return send(res, 400, { ok: false, err: 'params' });
        const u = db.users[email];
        if (!u) return send(res, 404, { ok: false, err: 'no_user' });
        const h = await pbkdf2(password, u.salt);
        if (h !== u.pw) return send(res, 401, { ok: false, err: 'bad_password' });
        const b = bindDevice(email, device_fp);
        if (!b.ok) return send(res, 409, { ok: false, err: b.err });
        return send(res, 200, { ok: true, license: issue(device_fp, email) });
      }
      if (url.pathname === '/verify_code') {
        if (!email || !code || !device_fp) return send(res, 400, { ok: false, err: 'params' });
        if (!db.users[email]) return send(res, 404, { ok: false, err: 'need_register' });
        const chk = checkCode(email, code);
        if (!chk.ok) return send(res, 400, { ok: false, err: chk.err });
        const b = bindDevice(email, device_fp);
        if (!b.ok) return send(res, 409, { ok: false, err: b.err });
        delete db.codes[email]; save();
        return send(res, 200, { ok: true, license: issue(device_fp, email) });
      }
      if (url.pathname === '/heartbeat') {
        const parts = String(license || '').split('.');
        if (parts.length !== 2) return send(res, 400, { ok: false, err: 'format' });
        const f = parts[0].split('|');
        if (f[1] !== device_fp) return send(res, 401, { ok: false, err: 'device' });
        if (Date.now() > parseInt(f[3], 10)) return send(res, 401, { ok: false, err: 'expired' });
        const d = db.devices[device_fp];
        if (!d || d.status !== 'active') return send(res, 401, { ok: false, err: 'revoked' });
        d.seen = Date.now(); save();
        return send(res, 200, { ok: true });
      }
      return send(res, 404, { ok: false, err: 'not_found' });
    } catch (e) {
      console.error(e);
      return send(res, 500, { ok: false, err: 'server', msg: String(e.message || e) });
    }
  });
}).listen(PORT, () => console.log('listening on ' + PORT));
