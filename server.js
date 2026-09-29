import 'dotenv/config';
import express from 'express';
import http from 'http';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';
import multer from 'multer';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import jwt from 'jsonwebtoken';
import { Server as SocketIOServer } from 'socket.io';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = Number(process.env.PORT || 3000);
const APP_ORIGIN = process.env.APP_ORIGIN || `http://localhost:${PORT}`;
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(48).toString('hex');
const COOKIE_SECURE = String(process.env.COOKIE_SECURE || 'false') === 'true';

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, { cors: { origin: APP_ORIGIN, credentials: true } });

const dataDir = path.join(__dirname, 'data');
const uploadDir = path.join(__dirname, 'uploads');
const db = new Database(path.join(dataDir, 'nexora.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  email TEXT UNIQUE,
  password_hash TEXT,
  display_name TEXT NOT NULL,
  bio TEXT NOT NULL DEFAULT '',
  avatar_url TEXT NOT NULL DEFAULT '',
  cover_url TEXT NOT NULL DEFAULT '',
  provider TEXT NOT NULL DEFAULT 'local',
  provider_id TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(provider, provider_id)
);
CREATE TABLE IF NOT EXISTS posts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL DEFAULT '',
  media_url TEXT NOT NULL DEFAULT '',
  media_type TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  receiver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL DEFAULT '',
  media_url TEXT NOT NULL DEFAULT '',
  media_type TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS store_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  price REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'USD',
  cover_url TEXT NOT NULL DEFAULT '',
  purchase_url TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_pair ON messages(sender_id, receiver_id, created_at);
CREATE INDEX IF NOT EXISTS idx_store_created ON store_items(created_at DESC);
`);

app.disable('x-powered-by');
app.use(helmet({ crossOriginEmbedderPolicy: false, contentSecurityPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(cookieParser());
app.use('/uploads', express.static(uploadDir, { maxAge: '7d' }));
app.use(express.static(path.join(__dirname, 'public')));

const authLimiter = rateLimit({ windowMs: 10 * 60 * 1000, limit: 30, standardHeaders: 'draft-8', legacyHeaders: false });
const writeLimiter = rateLimit({ windowMs: 60 * 1000, limit: 90, standardHeaders: 'draft-8', legacyHeaders: false });

const upload = multer({
  dest: uploadDir,
  limits: { fileSize: 80 * 1024 * 1024, files: 1 },
  fileFilter: (_req, file, cb) => {
    const accepted = /^image\/(png|jpeg|webp|gif)$|^video\/(mp4|webm|quicktime)$|^audio\/(mpeg|mp4|webm|wav|ogg)$/.test(file.mimetype);
    cb(accepted ? null : new Error('نوع الملف غير مسموح'), accepted);
  }
});

function signSession(userId) {
  return jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: '14d', issuer: 'nexora' });
}
function setSession(res, userId) {
  res.cookie('nexora_session', signSession(userId), {
    httpOnly: true,
    sameSite: 'lax',
    secure: COOKIE_SECURE,
    maxAge: 14 * 24 * 60 * 60 * 1000,
    path: '/'
  });
}
function clearSession(res) { res.clearCookie('nexora_session', { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, path: '/' }); }
function currentUser(req) {
  try {
    const token = req.cookies.nexora_session;
    if (!token) return null;
    const decoded = jwt.verify(token, JWT_SECRET, { issuer: 'nexora' });
    return db.prepare('SELECT id, username, email, display_name, bio, avatar_url, cover_url, provider, created_at FROM users WHERE id=?').get(decoded.sub) || null;
  } catch { return null; }
}
function requireAuth(req, res, next) {
  const user = currentUser(req);
  if (!user) return res.status(401).json({ error: 'تسجيل الدخول مطلوب' });
  req.user = user;
  next();
}
function csrfToken(req) {
  if (!req.cookies.nexora_csrf) {
    const token = crypto.randomBytes(32).toString('base64url');
    req.res.cookie('nexora_csrf', token, { httpOnly: false, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: 24 * 60 * 60 * 1000, path: '/' });
    return token;
  }
  return req.cookies.nexora_csrf;
}
function requireCsrf(req, res, next) {
  const token = req.headers['x-csrf-token'] || req.body?._csrf;
  if (!token || token !== req.cookies.nexora_csrf) return res.status(403).json({ error: 'CSRF token غير صالح' });
  next();
}
function cleanText(v, max = 5000) { return String(v ?? '').trim().slice(0, max); }
function publicUser(user) { return { id: user.id, username: user.username, display_name: user.display_name, bio: user.bio, avatar_url: user.avatar_url, cover_url: user.cover_url, provider: user.provider }; }
function fileUrl(file) { return file ? `/uploads/${path.basename(file.path)}` : ''; }
function base64Url(buf) { return Buffer.from(buf).toString('base64url'); }
function randomState() { return crypto.randomBytes(24).toString('base64url'); }

app.get('/api/csrf', (req, res) => res.json({ csrfToken: csrfToken(req) }));
app.get('/api/me', (req, res) => res.json({ user: currentUser(req) }));

app.post('/api/register', authLimiter, requireCsrf, async (req, res) => {
  const username = cleanText(req.body.username, 24).toLowerCase().replace(/[^a-z0-9_]/g, '');
  const email = cleanText(req.body.email, 254).toLowerCase();
  const password = String(req.body.password || '');
  const displayName = cleanText(req.body.displayName, 60) || username;
  if (username.length < 3 || password.length < 8) return res.status(400).json({ error: 'اسم المستخدم 3 أحرف على الأقل وكلمة المرور 8 أحرف على الأقل' });
  if (email && !/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: 'البريد الإلكتروني غير صالح' });
  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare('INSERT INTO users (username,email,password_hash,display_name) VALUES (?,?,?,?)').run(username, email || null, hash, displayName);
    setSession(res, result.lastInsertRowid);
    res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid)) });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'اسم المستخدم أو البريد مستخدم بالفعل' });
    res.status(500).json({ error: 'تعذر إنشاء الحساب' });
  }
});

app.post('/api/login', authLimiter, requireCsrf, async (req, res) => {
  const identifier = cleanText(req.body.identifier, 254).toLowerCase();
  const password = String(req.body.password || '');
  const user = db.prepare('SELECT * FROM users WHERE username = ? OR email = ?').get(identifier, identifier);
  if (!user || !user.password_hash || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: 'بيانات الدخول غير صحيحة' });
  setSession(res, user.id);
  res.json({ user: publicUser(user) });
});

app.post('/api/logout', requireCsrf, (req, res) => { clearSession(res); res.json({ ok: true }); });

app.get('/api/users', requireAuth, (req, res) => {
  const q = cleanText(req.query.q, 50).replace(/%/g, '');
  const users = db.prepare(`SELECT id,username,display_name,avatar_url,bio FROM users WHERE id != ? AND (username LIKE ? OR display_name LIKE ?) ORDER BY display_name ASC LIMIT 50`)
    .all(req.user.id, `%${q}%`, `%${q}%`);
  res.json({ users });
});

app.get('/api/users/:id', requireAuth, (req, res) => {
  const user = db.prepare('SELECT id,username,display_name,bio,avatar_url,cover_url,provider,created_at FROM users WHERE id=?').get(Number(req.params.id));
  if (!user) return res.status(404).json({ error: 'المستخدم غير موجود' });
  res.json({ user });
});

app.put('/api/profile', requireAuth, requireCsrf, writeLimiter, (req, res) => {
  const displayName = cleanText(req.body.displayName, 60);
  const bio = cleanText(req.body.bio, 280);
  const username = cleanText(req.body.username, 24).toLowerCase().replace(/[^a-z0-9_]/g, '');
  if (username.length < 3 || displayName.length < 1) return res.status(400).json({ error: 'البيانات غير صالحة' });
  try {
    db.prepare('UPDATE users SET username=?, display_name=?, bio=? WHERE id=?').run(username, displayName, bio, req.user.id);
    res.json({ user: publicUser(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id)) });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'اسم المستخدم مستخدم بالفعل' });
    res.status(500).json({ error: 'تعذر حفظ الملف الشخصي' });
  }
});

app.post('/api/profile/avatar', requireAuth, requireCsrf, upload.single('file'), (req, res) => {
  if (!req.file || !/^image\//.test(req.file.mimetype)) return res.status(400).json({ error: 'أرسل صورة فقط' });
  const url = fileUrl(req.file);
  db.prepare('UPDATE users SET avatar_url=? WHERE id=?').run(url, req.user.id);
  res.json({ url });
});

app.post('/api/profile/cover', requireAuth, requireCsrf, upload.single('file'), (req, res) => {
  if (!req.file || !/^image\//.test(req.file.mimetype)) return res.status(400).json({ error: 'أرسل صورة فقط' });
  const url = fileUrl(req.file);
  db.prepare('UPDATE users SET cover_url=? WHERE id=?').run(url, req.user.id);
  res.json({ url });
});

app.get('/api/posts', requireAuth, (req, res) => {
  const posts = db.prepare(`SELECT p.id,p.body,p.media_url,p.media_type,p.created_at,u.id user_id,u.username,u.display_name,u.avatar_url
    FROM posts p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100`).all();
  res.json({ posts });
});

app.post('/api/posts', requireAuth, requireCsrf, writeLimiter, upload.single('media'), (req, res) => {
  const body = cleanText(req.body.body, 5000);
  if (!body && !req.file) return res.status(400).json({ error: 'المنشور فارغ' });
  const mediaUrl = fileUrl(req.file);
  const mediaType = req.file?.mimetype || '';
  const result = db.prepare('INSERT INTO posts (user_id,body,media_url,media_type) VALUES (?,?,?,?)').run(req.user.id, body, mediaUrl, mediaType);
  const post = db.prepare(`SELECT p.id,p.body,p.media_url,p.media_type,p.created_at,u.id user_id,u.username,u.display_name,u.avatar_url FROM posts p JOIN users u ON u.id=p.user_id WHERE p.id=?`).get(result.lastInsertRowid);
  io.emit('feed:new', post);
  res.json({ post });
});

app.get('/api/messages/:userId', requireAuth, (req, res) => {
  const other = Number(req.params.userId);
  const messages = db.prepare(`SELECT m.id,m.sender_id,m.receiver_id,m.body,m.media_url,m.media_type,m.created_at,
      su.display_name sender_name,su.username sender_username,su.avatar_url sender_avatar
      FROM messages m JOIN users su ON su.id=m.sender_id
      WHERE (m.sender_id=? AND m.receiver_id=?) OR (m.sender_id=? AND m.receiver_id=?)
      ORDER BY m.id ASC LIMIT 300`).all(req.user.id, other, other, req.user.id);
  res.json({ messages });
});

app.post('/api/messages/:userId', requireAuth, requireCsrf, writeLimiter, upload.single('media'), (req, res) => {
  const receiverId = Number(req.params.userId);
  if (!db.prepare('SELECT 1 FROM users WHERE id=?').get(receiverId)) return res.status(404).json({ error: 'المستخدم غير موجود' });
  const body = cleanText(req.body.body, 4000);
  if (!body && !req.file) return res.status(400).json({ error: 'الرسالة فارغة' });
  const mediaUrl = fileUrl(req.file);
  const mediaType = req.file?.mimetype || '';
  const result = db.prepare('INSERT INTO messages (sender_id,receiver_id,body,media_url,media_type) VALUES (?,?,?,?,?)')
    .run(req.user.id, receiverId, body, mediaUrl, mediaType);
  const msg = db.prepare(`SELECT m.*, su.display_name sender_name,su.username sender_username,su.avatar_url sender_avatar
    FROM messages m JOIN users su ON su.id=m.sender_id WHERE m.id=?`).get(result.lastInsertRowid);
  io.to(`user:${receiverId}`).emit('chat:message', msg);
  io.to(`user:${req.user.id}`).emit('chat:message', msg);
  res.json({ message: msg });
});

app.post('/api/store', requireAuth, requireCsrf, writeLimiter, upload.single('cover'), (req, res) => {
  const name = cleanText(req.body.name, 100);
  const description = cleanText(req.body.description, 2000);
  const price = Number(req.body.price || 0);
  const currency = cleanText(req.body.currency || 'USD', 8).toUpperCase();
  const purchaseUrl = cleanText(req.body.purchaseUrl, 500);
  if (!name) return res.status(400).json({ error: 'اسم المنتج مطلوب' });
  if (!Number.isFinite(price) || price < 0) return res.status(400).json({ error: 'السعر غير صالح' });
  const coverUrl = fileUrl(req.file);
  const result = db.prepare('INSERT INTO store_items (seller_id,name,description,price,currency,cover_url,purchase_url) VALUES (?,?,?,?,?,?,?)')
    .run(req.user.id, name, description, price, currency, coverUrl, purchaseUrl);
  const item = db.prepare(`SELECT s.*,u.username seller_username,u.display_name seller_name FROM store_items s JOIN users u ON u.id=s.seller_id WHERE s.id=?`).get(result.lastInsertRowid);
  io.emit('store:new', item);
  res.json({ item });
});

app.get('/api/store', requireAuth, (req, res) => {
  const items = db.prepare(`SELECT s.*,u.username seller_username,u.display_name seller_name FROM store_items s JOIN users u ON u.id=s.seller_id ORDER BY s.id DESC LIMIT 100`).all();
  res.json({ items });
});

async function providerUser(provider, code) {
  if (provider === 'google') {
    const params = new URLSearchParams({ code, client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: process.env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code' });
    const tok = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: params }).then(r => r.json());
    if (!tok.access_token) throw new Error(tok.error_description || 'Google token exchange failed');
    const u = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { authorization: `Bearer ${tok.access_token}` } }).then(r => r.json());
    return { providerId: u.sub, email: u.email || null, displayName: u.name || u.email || 'Google user', avatar: u.picture || '' };
  }
  if (provider === 'tiktok') {
    const params = new URLSearchParams({ client_key: process.env.TIKTOK_CLIENT_KEY, client_secret: process.env.TIKTOK_CLIENT_SECRET, code, grant_type: 'authorization_code', redirect_uri: process.env.TIKTOK_REDIRECT_URI });
    const tok = await fetch('https://open.tiktokapis.com/v2/oauth/token/', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: params }).then(r => r.json());
    if (!tok.access_token) throw new Error(tok.error_description || 'TikTok token exchange failed');
    const u = await fetch('https://open.tiktokapis.com/v2/user/info/?fields=open_id,avatar_url,display_name,union_id', { headers: { authorization: `Bearer ${tok.access_token}` } }).then(r => r.json());
    const d = u.data?.user || {};
    return { providerId: d.open_id, email: null, displayName: d.display_name || 'TikTok user', avatar: d.avatar_url || '' };
  }
  if (provider === 'facebook') {
    const version = process.env.FACEBOOK_GRAPH_VERSION || 'v24.0';
    const tokenUrl = `https://graph.facebook.com/${version}/oauth/access_token?${new URLSearchParams({ client_id: process.env.FACEBOOK_APP_ID, client_secret: process.env.FACEBOOK_APP_SECRET, redirect_uri: process.env.FACEBOOK_REDIRECT_URI, code })}`;
    const tok = await fetch(tokenUrl).then(r => r.json());
    if (!tok.access_token) throw new Error(tok.error?.message || 'Facebook token exchange failed');
    const u = await fetch(`https://graph.facebook.com/${version}/me?${new URLSearchParams({ fields: 'id,name,email,picture.width(512).height(512)', access_token: tok.access_token })}`).then(r => r.json());
    if (!u.id) throw new Error(u.error?.message || 'Facebook profile lookup failed');
    return { providerId: u.id, email: u.email || null, displayName: u.name || 'Facebook user', avatar: u.picture?.data?.url || '' };
  }
  throw new Error('Unsupported provider');
}

function providerConfig(provider) {
  if (provider === 'google') return { id: process.env.GOOGLE_CLIENT_ID, redirect: process.env.GOOGLE_REDIRECT_URI, authorize: 'https://accounts.google.com/o/oauth2/v2/auth', scope: 'openid email profile' };
  if (provider === 'tiktok') return { id: process.env.TIKTOK_CLIENT_KEY, redirect: process.env.TIKTOK_REDIRECT_URI, authorize: 'https://www.tiktok.com/v2/auth/authorize/', scope: 'user.info.basic' };
  if (provider === 'facebook') return { id: process.env.FACEBOOK_APP_ID, redirect: process.env.FACEBOOK_REDIRECT_URI, authorize: `https://www.facebook.com/${process.env.FACEBOOK_GRAPH_VERSION || 'v24.0'}/dialog/oauth`, scope: 'public_profile,email' };
  return null;
}

app.get('/auth/:provider', (req, res) => {
  const provider = req.params.provider;
  if (!['google', 'tiktok', 'facebook'].includes(provider)) return res.status(404).send('Provider not configured.');
  const c = providerConfig(provider);
  if (!c?.id || !c?.redirect) return res.status(503).send(`Provider ${provider} needs environment credentials.`);
  const state = randomState();
  res.cookie(`oauth_state_${provider}`, state, { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: 10 * 60 * 1000, path: '/' });
  const params = new URLSearchParams({ client_id: c.id, redirect_uri: c.redirect, response_type: 'code', scope: c.scope, state });
  if (provider === 'tiktok') params.set('response_type', 'code');
  res.redirect(`${c.authorize}?${params.toString()}`);
});

app.get('/auth/:provider/callback', async (req, res) => {
  const provider = req.params.provider;
  try {
    const state = req.cookies[`oauth_state_${provider}`];
    if (!state || state !== req.query.state) return res.status(400).send('OAuth state validation failed.');
    if (!req.query.code) return res.status(400).send('OAuth code missing.');
    const p = await providerUser(provider, req.query.code);
    let user = db.prepare('SELECT * FROM users WHERE provider=? AND provider_id=?').get(provider, p.providerId);
    if (!user) {
      const usernameBase = (p.email?.split('@')[0] || `${provider}_${p.providerId}`).toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 20) || provider;
      let username = usernameBase;
      let n = 1;
      while (db.prepare('SELECT 1 FROM users WHERE username=?').get(username)) username = `${usernameBase}${n++}`;
      const result = db.prepare('INSERT INTO users (username,email,display_name,avatar_url,provider,provider_id) VALUES (?,?,?,?,?,?)').run(username, p.email, p.displayName, p.avatar, provider, p.providerId);
      user = db.prepare('SELECT * FROM users WHERE id=?').get(result.lastInsertRowid);
    } else {
      db.prepare('UPDATE users SET display_name=?,avatar_url=?,email=COALESCE(email,?) WHERE id=?').run(p.displayName, p.avatar, p.email, user.id);
      user = db.prepare('SELECT * FROM users WHERE id=?').get(user.id);
    }
    clearSession(res);
    setSession(res, user.id);
    res.redirect('/');
  } catch (e) {
    res.status(500).send(`OAuth error: ${String(e.message || e)}`);
  }
});

app.get('*', (req, res) => {
  if (req.path.startsWith('/api/') || req.path.startsWith('/auth/') || req.path.startsWith('/uploads/')) return res.status(404).end();
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

io.use((socket, next) => {
  try {
    const cookie = socket.handshake.headers.cookie || '';
    const match = cookie.match(/(?:^|; )nexora_session=([^;]+)/);
    if (!match) return next(new Error('unauthorized'));
    const payload = jwt.verify(decodeURIComponent(match[1]), JWT_SECRET, { issuer: 'nexora' });
    const user = db.prepare('SELECT id,display_name,username,avatar_url FROM users WHERE id=?').get(payload.sub);
    if (!user) return next(new Error('unauthorized'));
    socket.user = user;
    next();
  } catch { next(new Error('unauthorized')); }
});

io.on('connection', (socket) => {
  socket.join(`user:${socket.user.id}`);
  socket.on('call:offer', ({ to, offer }) => io.to(`user:${Number(to)}`).emit('call:offer', { from: socket.user.id, fromName: socket.user.display_name, offer }));
  socket.on('call:answer', ({ to, answer }) => io.to(`user:${Number(to)}`).emit('call:answer', { from: socket.user.id, answer }));
  socket.on('call:ice', ({ to, candidate }) => io.to(`user:${Number(to)}`).emit('call:ice', { from: socket.user.id, candidate }));
  socket.on('call:hangup', ({ to }) => io.to(`user:${Number(to)}`).emit('call:hangup', { from: socket.user.id }));
});

server.listen(PORT, () => console.log(`NEXORA running at ${APP_ORIGIN}`));
