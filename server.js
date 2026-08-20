// server.js — FastBites Backend
// Pure Node.js (no framework). Uses Turso for persistent hosting, local SQLite for testing.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { db, hashPassword, verifyPassword, initDb } = require('./db');

const PORT = process.env.PORT || 4000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// ---------- In-memory admin session tokens with expiry (24 hours) ----------
const adminSessions = new Map(); // token -> expiryTimestamp
const SESSION_DURATION_MS = 24 * 60 * 60 * 1000;

function newAdminSession() {
  const token = crypto.randomBytes(24).toString('hex');
  adminSessions.set(token, Date.now() + SESSION_DURATION_MS);
  return token;
}
function isValidAdminSession(token) {
  const expiry = adminSessions.get(token);
  if (!expiry) return false;
  if (Date.now() > expiry) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}
setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of adminSessions) {
    if (now > expiry) adminSessions.delete(token);
  }
}, 60 * 60 * 1000);

// ---------- User session tokens (so profile edits / orders can't be spoofed by guessing IDs) ----------
const userSessions = new Map(); // token -> { userId, expiry }
const USER_SESSION_DURATION_MS = 30 * 24 * 60 * 60 * 1000; // 30 days

function newUserSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  userSessions.set(token, { userId, expiry: Date.now() + USER_SESSION_DURATION_MS });
  return token;
}
function getUserIdFromRequest(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const session = userSessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiry) {
    userSessions.delete(token);
    return null;
  }
  return session.userId;
}
setInterval(() => {
  const now = Date.now();
  for (const [token, session] of userSessions) {
    if (now > session.expiry) userSessions.delete(token);
  }
}, 60 * 60 * 1000);

// ---------- Basic brute-force / spam protection (per IP + identifier) ----------
const loginAttempts = new Map();
const RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000; // 15 minutes
const RATE_LIMIT_MAX_ATTEMPTS = 8;
const ORDER_RATE_LIMIT_MAX = 20; // orders per 15 min per IP

function isRateLimited(key, max = RATE_LIMIT_MAX_ATTEMPTS) {
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.delete(key);
    return false;
  }
  return entry.count >= max;
}
function recordFailedAttempt(key) {
  const entry = loginAttempts.get(key);
  if (!entry || Date.now() - entry.firstAttempt > RATE_LIMIT_WINDOW_MS) {
    loginAttempts.set(key, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count++;
  }
}
function clearAttempts(key) { loginAttempts.delete(key); }
function clientKey(req, identifier) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  return `${ip}:${identifier}`;
}

// ---------- Helpers ----------
function sendJson(res, status, data) {
  const body = JSON.stringify(data);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'strict-origin-when-cross-origin'
  });
  res.end(body);
}

const MAX_BODY_SIZE = 2 * 1024 * 1024;

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    req.on('data', chunk => {
      size += chunk.length;
      if (size > MAX_BODY_SIZE) {
        reject(new Error('Payload too large'));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function requireAdmin(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  return isValidAdminSession(token);
}

function serveStatic(req, res, urlPath) {
  let filePath = urlPath === '/' ? '/index.html' : urlPath;
  filePath = path.join(PUBLIC_DIR, filePath);

  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403); res.end('Forbidden'); return;
  }
  if (path.basename(filePath).startsWith('.')) {
    res.writeHead(404); res.end('Not found'); return;
  }

  fs.readFile(filePath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
      return;
    }
    const ext = path.extname(filePath);
    const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript' };
    res.writeHead(200, {
      'Content-Type': types[ext] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'X-Frame-Options': 'DENY',
      'Referrer-Policy': 'strict-origin-when-cross-origin'
    });
    res.end(content);
  });
}

// ---------- Route handlers ----------

async function handleApi(req, res, urlPath, query) {
  const method = req.method;

  // ===== ADMIN AUTH =====
  if (urlPath === '/api/admin/login' && method === 'POST') {
    const { username, password } = await readBody(req);
    const key = clientKey(req, 'admin:' + (username || ''));
    if (isRateLimited(key)) {
      return sendJson(res, 429, { error: 'Too many failed attempts. Please try again in a few minutes.' });
    }
    const admin = await db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    if (!admin || !verifyPassword(password || '', admin.password_hash)) {
      recordFailedAttempt(key);
      return sendJson(res, 401, { error: 'Invalid username or password' });
    }
    clearAttempts(key);
    if (!admin.password_hash.includes(':')) {
      await db.prepare('UPDATE admins SET password_hash = ? WHERE id = ?').run(hashPassword(password), admin.id);
    }
    const token = newAdminSession();
    return sendJson(res, 200, { token, username: admin.username });
  }

  if (urlPath === '/api/admin/logout' && method === 'POST') {
    const auth = req.headers['authorization'] || '';
    const token = auth.replace('Bearer ', '').trim();
    adminSessions.delete(token);
    return sendJson(res, 200, { success: true });
  }

  // Everything below requires an admin token
  if (urlPath.startsWith('/api/admin') || ['/api/users', '/api/orders', '/api/categories', '/api/items', '/api/banners'].some(p => urlPath.startsWith(p))) {
    if (!requireAdmin(req)) {
      return sendJson(res, 401, { error: 'Unauthorized. Please login again.' });
    }
  }

  // ===== USERS (with computed stats) =====
  if (urlPath === '/api/users' && method === 'GET') {
    const users = await db.prepare('SELECT id, name, username, mobile, address, created_at FROM users').all();
    const withStats = [];
    for (const u of users) {
      const total = (await db.prepare('SELECT COUNT(*) c FROM orders WHERE user_id = ?').get(u.id)).c;
      const cancelled = (await db.prepare("SELECT COUNT(*) c FROM orders WHERE user_id = ? AND order_status = 'CANCELLED'").get(u.id)).c;
      const delivered = (await db.prepare("SELECT COUNT(*) c FROM orders WHERE user_id = ? AND order_status = 'DELIVERED'").get(u.id)).c;
      withStats.push({ ...u, total_orders: total, cancelled_orders: cancelled, successful_orders: delivered });
    }
    return sendJson(res, 200, withStats);
  }

  // ===== ORDERS =====
  if (urlPath === '/api/orders' && method === 'GET') {
    const orders = await db.prepare(`
      SELECT o.*, u.name as customer_name, u.username, u.mobile, u.address as user_address
      FROM orders o JOIN users u ON u.id = o.user_id
      ORDER BY o.created_at DESC
    `).all();
    return sendJson(res, 200, orders.map(o => ({ ...o, items: JSON.parse(o.items_json) })));
  }

  const orderStatusMatch = urlPath.match(/^\/api\/orders\/(\d+)\/status$/);
  if (orderStatusMatch && method === 'PATCH') {
    const id = orderStatusMatch[1];
    const { order_status } = await readBody(req);
    const valid = ['PLACED', 'PREPARING', 'COOKING', 'OUT_FOR_DELIVERY', 'DELIVERED', 'CANCELLED'];
    if (!valid.includes(order_status)) return sendJson(res, 400, { error: 'Invalid status' });
    await db.prepare("UPDATE orders SET order_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(order_status, id);
    return sendJson(res, 200, { success: true });
  }

  const paymentStatusMatch = urlPath.match(/^\/api\/orders\/(\d+)\/payment$/);
  if (paymentStatusMatch && method === 'PATCH') {
    const id = paymentStatusMatch[1];
    const { payment_status } = await readBody(req);
    if (!['PAID', 'PENDING'].includes(payment_status)) return sendJson(res, 400, { error: 'Invalid payment status' });
    await db.prepare("UPDATE orders SET payment_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(payment_status, id);
    return sendJson(res, 200, { success: true });
  }

  // ===== CATEGORIES =====
  if (urlPath === '/api/categories' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM categories ORDER BY name').all());
  }
  if (urlPath === '/api/categories' && method === 'POST') {
    const { name } = await readBody(req);
    if (!name || !name.trim()) return sendJson(res, 400, { error: 'Category name required' });
    try {
      const info = await db.prepare('INSERT INTO categories (name) VALUES (?)').run(name.trim());
      return sendJson(res, 201, { id: Number(info.lastInsertRowid), name: name.trim() });
    } catch (e) {
      return sendJson(res, 400, { error: 'Category already exists' });
    }
  }
  const catDeleteMatch = urlPath.match(/^\/api\/categories\/(\d+)$/);
  if (catDeleteMatch && method === 'DELETE') {
    await db.prepare('DELETE FROM categories WHERE id = ?').run(catDeleteMatch[1]);
    return sendJson(res, 200, { success: true });
  }

  // ===== ITEMS =====
  if (urlPath === '/api/items' && method === 'GET') {
    const items = await db.prepare(`
      SELECT items.*, categories.name as category_name
      FROM items LEFT JOIN categories ON categories.id = items.category_id
      ORDER BY items.created_at DESC
    `).all();
    return sendJson(res, 200, items);
  }
  if (urlPath === '/api/items' && method === 'POST') {
    const { name, price, category_id, image_url, description, long_description, prep_time, rating } = await readBody(req);
    if (!name || !price) return sendJson(res, 400, { error: 'Name and price are required' });
    const info = await db.prepare(`
      INSERT INTO items (name, price, category_id, image_url, description, long_description, prep_time, rating)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      name.trim(), price, category_id || null, image_url || '', description || '',
      long_description || description || '', prep_time || '20 mins', rating || 4.5
    );
    return sendJson(res, 201, { id: Number(info.lastInsertRowid) });
  }
  const itemUpdateMatch = urlPath.match(/^\/api\/items\/(\d+)$/);
  if (itemUpdateMatch && method === 'PUT') {
    const { name, price, category_id, image_url, description, long_description, prep_time, rating, available } = await readBody(req);
    await db.prepare(`
      UPDATE items SET name = ?, price = ?, category_id = ?, image_url = ?, description = ?,
        long_description = ?, prep_time = ?, rating = ?, available = ?
      WHERE id = ?
    `).run(
      name, price, category_id || null, image_url || '', description || '',
      long_description || description || '', prep_time || '20 mins', rating || 4.5,
      available ? 1 : 0, itemUpdateMatch[1]
    );
    return sendJson(res, 200, { success: true });
  }
  if (itemUpdateMatch && method === 'DELETE') {
    await db.prepare('DELETE FROM items WHERE id = ?').run(itemUpdateMatch[1]);
    return sendJson(res, 200, { success: true });
  }

  // ===== BANNERS =====
  if (urlPath === '/api/banners' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM banners ORDER BY sort_order, created_at DESC').all());
  }
  if (urlPath === '/api/banners' && method === 'POST') {
    const { title, image_url, video_url, sort_order } = await readBody(req);
    if (!image_url && !video_url) return sendJson(res, 400, { error: 'Provide an image_url or video_url' });
    const info = await db.prepare(`
      INSERT INTO banners (title, image_url, video_url, sort_order) VALUES (?, ?, ?, ?)
    `).run(title || '', image_url || '', video_url || '', sort_order || 0);
    return sendJson(res, 201, { id: Number(info.lastInsertRowid) });
  }
  const bannerToggleMatch = urlPath.match(/^\/api\/banners\/(\d+)\/toggle$/);
  if (bannerToggleMatch && method === 'PATCH') {
    const banner = await db.prepare('SELECT * FROM banners WHERE id = ?').get(bannerToggleMatch[1]);
    if (!banner) return sendJson(res, 404, { error: 'Not found' });
    await db.prepare('UPDATE banners SET active = ? WHERE id = ?').run(banner.active ? 0 : 1, bannerToggleMatch[1]);
    return sendJson(res, 200, { success: true });
  }
  const bannerDeleteMatch = urlPath.match(/^\/api\/banners\/(\d+)$/);
  if (bannerDeleteMatch && method === 'DELETE') {
    await db.prepare('DELETE FROM banners WHERE id = ?').run(bannerDeleteMatch[1]);
    return sendJson(res, 200, { success: true });
  }

  // ===== PUBLIC: for the FRONTEND app (no admin token needed) =====
  if (urlPath === '/api/public/signup' && method === 'POST') {
    const { name, username, mobile, address, password } = await readBody(req);
    if (!name || !username || !mobile || !password) return sendJson(res, 400, { error: 'Missing fields' });
    if (!/^[0-9]{10}$/.test(mobile)) return sendJson(res, 400, { error: 'Enter a valid 10-digit mobile number' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return sendJson(res, 400, { error: 'Username must be 3-20 characters (letters, numbers, underscore only)' });
    if (name.length > 100 || (address && address.length > 300)) return sendJson(res, 400, { error: 'Name or address is too long' });
    if (password.length < 6) return sendJson(res, 400, { error: 'Password must be at least 6 characters' });

    const signupKey = clientKey(req, 'signup');
    if (isRateLimited(signupKey, 5)) {
      return sendJson(res, 429, { error: 'Too many signup attempts from this device. Please try again later.' });
    }

    try {
      const info = await db.prepare(`
        INSERT INTO users (name, username, mobile, address, password_hash) VALUES (?, ?, ?, ?, ?)
      `).run(name, username, mobile, address || '', hashPassword(password));
      const userId = Number(info.lastInsertRowid);
      const token = newUserSession(userId);
      return sendJson(res, 201, { id: userId, name, username, mobile, address, token });
    } catch (e) {
      recordFailedAttempt(signupKey);
      return sendJson(res, 400, { error: 'Mobile or username already registered' });
    }
  }
  const publicProfileMatch = urlPath.match(/^\/api\/public\/users\/(\d+)$/);
  if (publicProfileMatch && method === 'PUT') {
    const requestedId = Number(publicProfileMatch[1]);
    const authedUserId = getUserIdFromRequest(req);
    if (!authedUserId || authedUserId !== requestedId) {
      return sendJson(res, 401, { error: 'Please log in again to update your profile.' });
    }
    const { name, username, address } = await readBody(req);
    if (!name || !username) return sendJson(res, 400, { error: 'Name and username are required' });
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return sendJson(res, 400, { error: 'Username must be 3-20 characters (letters, numbers, underscore only)' });
    if (name.length > 100 || (address && address.length > 300)) return sendJson(res, 400, { error: 'Name or address is too long' });
    try {
      await db.prepare('UPDATE users SET name = ?, username = ?, address = ? WHERE id = ?')
        .run(name, username, address || '', requestedId);
      const user = await db.prepare('SELECT id, name, username, mobile, address FROM users WHERE id = ?').get(requestedId);
      if (!user) return sendJson(res, 404, { error: 'User not found' });
      return sendJson(res, 200, user);
    } catch (e) {
      return sendJson(res, 400, { error: 'That username is already taken' });
    }
  }

  if (urlPath === '/api/public/login' && method === 'POST') {
    const { mobile, password } = await readBody(req);
    const key = clientKey(req, 'user:' + (mobile || ''));
    if (isRateLimited(key)) {
      return sendJson(res, 429, { error: 'Too many failed attempts. Please try again in a few minutes.' });
    }
    const user = await db.prepare('SELECT * FROM users WHERE mobile = ?').get(mobile);
    if (!user || !verifyPassword(password || '', user.password_hash)) {
      recordFailedAttempt(key);
      return sendJson(res, 401, { error: 'Invalid mobile number or password' });
    }
    clearAttempts(key);
    if (!user.password_hash.includes(':')) {
      await db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(hashPassword(password), user.id);
    }
    const { password_hash, ...safeUser } = user;
    const token = newUserSession(user.id);
    return sendJson(res, 200, { ...safeUser, token });
  }
  if (urlPath === '/api/public/order' && method === 'POST') {
    const authedUserId = getUserIdFromRequest(req);
    if (!authedUserId) return sendJson(res, 401, { error: 'Please log in again to place an order.' });

    const orderKey = clientKey(req, 'order');
    if (isRateLimited(orderKey, ORDER_RATE_LIMIT_MAX)) {
      return sendJson(res, 429, { error: 'Too many orders placed from this device. Please try again later.' });
    }

    const { items, total, payment_mode, delivery_address } = await readBody(req);
    if (!Array.isArray(items) || items.length === 0 || items.length > 50) {
      return sendJson(res, 400, { error: 'Invalid items in order' });
    }
    if (typeof total !== 'number' || total <= 0 || total > 500000) {
      return sendJson(res, 400, { error: 'Invalid order total' });
    }
    recordFailedAttempt(orderKey);
    const payment_status = payment_mode === 'UPI' ? 'PAID' : 'PENDING';
    const info = await db.prepare(`
      INSERT INTO orders (user_id, items_json, total, payment_mode, payment_status, delivery_address)
      VALUES (?, ?, ?, ?, ?, ?)
    `).run(authedUserId, JSON.stringify(items), total, payment_mode || 'COD', payment_status, (delivery_address || '').slice(0, 500));
    return sendJson(res, 201, { id: Number(info.lastInsertRowid) });
  }
  const myOrdersMatch = urlPath.match(/^\/api\/public\/orders\/(\d+)$/);
  if (myOrdersMatch && method === 'GET') {
    const requestedId = Number(myOrdersMatch[1]);
    const authedUserId = getUserIdFromRequest(req);
    if (!authedUserId || authedUserId !== requestedId) {
      return sendJson(res, 401, { error: 'Please log in again to view your orders.' });
    }
    const orders = await db.prepare(`
      SELECT * FROM orders WHERE user_id = ? ORDER BY created_at DESC
    `).all(requestedId);
    return sendJson(res, 200, orders.map(o => ({ ...o, items: JSON.parse(o.items_json) })));
  }
  // Single order detail — used for "view full details" on a specific order
  const myOrderDetailMatch = urlPath.match(/^\/api\/public\/order\/(\d+)$/);
  if (myOrderDetailMatch && method === 'GET') {
    const orderId = Number(myOrderDetailMatch[1]);
    const authedUserId = getUserIdFromRequest(req);
    if (!authedUserId) return sendJson(res, 401, { error: 'Please log in again.' });
    const order = await db.prepare('SELECT * FROM orders WHERE id = ?').get(orderId);
    if (!order || order.user_id !== authedUserId) return sendJson(res, 404, { error: 'Order not found' });
    return sendJson(res, 200, { ...order, items: JSON.parse(order.items_json) });
  }

  if (urlPath === '/api/public/menu' && method === 'GET') {
    const items = await db.prepare(`
      SELECT items.*, categories.name as category_name FROM items
      LEFT JOIN categories ON categories.id = items.category_id
      WHERE available = 1
    `).all();
    return sendJson(res, 200, items);
  }
  if (urlPath === '/api/public/categories' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM categories ORDER BY name').all());
  }
  if (urlPath === '/api/public/banners' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM banners WHERE active = 1 ORDER BY sort_order').all());
  }

  return sendJson(res, 404, { error: 'Route not found' });
}

// ---------- Server ----------
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const urlPath = parsedUrl.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    });
    return res.end();
  }

  if (urlPath.startsWith('/api/')) {
    try {
      await handleApi(req, res, urlPath, parsedUrl.searchParams);
    } catch (e) {
      console.error('[API ERROR]', req.method, urlPath, e);
      if (e.message === 'Payload too large') {
        sendJson(res, 413, { error: 'Request too large' });
      } else {
        sendJson(res, 500, { error: 'Something went wrong. Please try again.' });
      }
    }
    return;
  }

  serveStatic(req, res, urlPath);
});

// Initialize the database (create tables, seed admin/categories) BEFORE accepting requests
initDb().then(() => {
  server.listen(PORT, () => {
    console.log(`\n🚀 FastBites backend running at http://localhost:${PORT}`);
    console.log(`👉 Admin panel: http://localhost:${PORT}/admin/login.html`);
    console.log(`   Admin login: check the "ADMIN LOGIN CREATED" message above (shown once on first run)\n`);
  });
}).catch(err => {
  console.error('❌ Failed to initialize database:', err);
  process.exit(1);
});
