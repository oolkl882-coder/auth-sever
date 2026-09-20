const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const DB_FILE = path.join(__dirname, 'keys.json');

// load db
let db = { keys: {}, sessions: {} };
if (fs.existsSync(DB_FILE)) {
  db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
function save() {
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
}

const app = express();
app.use(express.json());

const ADMIN_SECRET = 'doi_cai_nay_thanh_chuoi_dai_kho_doan'; // maker đổi

function genKey(prefix = 'MIMI') {
  const raw = crypto.randomBytes(12).toString('hex').toUpperCase();
  return `${prefix}-${raw.match(/.{1,8}/g).join('-')}`;
}

// trang chủ
app.get('/', (req, res) => res.send('auth server ok'));

// trang get key
app.get('/getkey', (req, res) => {
  res.sendFile(path.join(__dirname, 'getkey.html'));
});

// public gen key (user tự lấy)
app.post('/public/gen', (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ error: 'nhap ten' });

  const key = genKey();
  const expires_at = Date.now() + 24 * 3600 * 1000; // 1 ngày
  db.keys[key] = { hwid: null, expires_at, note: `public:${name}`, created_at: Date.now() };
  save();

  res.json({ key, expires_at });
});

// admin tạo key
app.post('/admin/gen', (req, res) => {
  const { secret, duration_seconds, note } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'nope' });

  const key = genKey();
  const expires_at = Date.now() + duration_seconds * 1000;
  db.keys[key] = { hwid: null, expires_at, note: note || '', created_at: Date.now() };
  save();

  res.json({ key, expires_at });
});

// admin list
app.post('/admin/list', (req, res) => {
  const { secret } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'nope' });
  res.json(db.keys);
});

// admin revoke
app.post('/admin/revoke', (req, res) => {
  const { secret, key } = req.body;
  if (secret !== ADMIN_SECRET) return res.status(403).json({ error: 'nope' });
  delete db.keys[key];
  save();
  res.json({ ok: true });
});

// client verify key
app.post('/verify', (req, res) => {
  const { key, hwid } = req.body;
  if (!key || !hwid) return res.status(400).json({ error: 'missing' });

  const row = db.keys[key];
  if (!row) return res.status(401).json({ error: 'invalid key' });
  if (row.expires_at < Date.now()) return res.status(401).json({ error: 'expired' });

  if (!row.hwid) {
    row.hwid = hwid;
    save();
  } else if (row.hwid !== hwid) {
    return res.status(401).json({ error: 'hwid mismatch' });
  }

  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = { key, hwid, created_at: Date.now() };
  save();

  res.json({
    ok: true,
    token,
    expires_at: row.expires_at,
    remaining_seconds: Math.floor((row.expires_at - Date.now()) / 1000)
  });
});

// check token
app.post('/token/check', (req, res) => {
  const { token, hwid } = req.body;
  const s = db.sessions[token];
  if (!s || s.hwid !== hwid) return res.status(401).json({ error: 'bad token' });

  const k = db.keys[s.key];
  if (!k || k.expires_at < Date.now()) return res.status(401).json({ error: 'expired' });

  res.json({ ok: true, expires_at: k.expires_at });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('server on ' + PORT));
