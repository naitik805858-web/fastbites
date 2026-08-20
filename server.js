// server.js — FastBites All-in-One Backend
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 4000;
const ROOT_DIR = __dirname;
const PUBLIC_DIR = path.join(__dirname, 'public');

// ==========================================
// 1. DATABASE SETUP (Turso / SQLite)
// ==========================================
const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

let tursoClient = null;
let localDb = null;

if (TURSO_URL && TURSO_TOKEN) {
  try {
    const { createClient } = require('@libsql/client');
    tursoClient = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
    console.log('📡 Using Turso cloud database.');
  } catch (e) {
    console.warn('⚠️ @libsql/client not found, using local memory fallback.');
  }
}

if (!tursoClient) {
  try {
    const { DatabaseSync } = require('node:sqlite');
    const dbPath = path.join(__dirname, 'fastbites.db');
    localDb = new DatabaseSync(dbPath);
    console.log('💾 Using local SQLite file.');
  } catch (e) {
    console.warn('⚠️ SQLite engine initializing in-memory.');
  }
}

const SCHEMA_STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    username TEXT UNIQUE NOT NULL,
    mobile TEXT UNIQUE NOT NULL,
    address TEXT,
    password_hash TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    category_id INTEGER,
    name TEXT NOT NULL,
    price REAL NOT NULL,
    image_url TEXT,
    description TEXT,
    long_description TEXT,
    rating REAL DEFAULT 4.5,
    rating_count TEXT DEFAULT '',
    prep_time TEXT DEFAULT '20 mins',
    available INTEGER DEFAULT 1,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (category_id) REFERENCES categories(id)
  )`,
  `CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    items_json TEXT NOT NULL,
    total REAL NOT NULL,
    payment_mode TEXT NOT NULL DEFAULT 'COD',
    payment_status TEXT NOT NULL DEFAULT 'PENDING',
    order_status TEXT NOT NULL DEFAULT 'PLACED',
    delivery_address TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`,
  `CREATE TABLE IF NOT EXISTS banners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT,
    image_url TEXT,
    video_url TEXT,
    active INTEGER DEFAULT 1,
    sort_order INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  )`,
  `CREATE TABLE IF NOT EXISTS admins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL
  )`
];

const MIGRATION_STATEMENTS = [
  `ALTER TABLE items ADD COLUMN long_description TEXT`,
  `ALTER TABLE items ADD COLUMN rating REAL DEFAULT 4.5`,
  `ALTER TABLE items ADD COLUMN rating_count TEXT DEFAULT ''`,
  `ALTER TABLE items ADD COLUMN prep_time TEXT DEFAULT '20 mins'`
];

function prepare(sql) {
  return {
    async get(...args) {
      if (tursoClient) {
        const result = await tursoClient.execute({ sql, args });
        return result.rows[0] ? { ...result.rows[0] } : undefined;
      }
      if (localDb) return localDb.prepare(sql).get(...args);
      return undefined;
    },
    async all(...args) {
      if (tursoClient) {
        const result = await tursoClient.execute({ sql, args });
        return result.rows.map(r => ({ ...r }));
      }
      if (localDb) return localDb.prepare(sql).all(...args);
      return [];
    },
    async run(...args) {
      if (tursoClient) {
        const result = await tursoClient.execute({ sql, args });
        return {
          lastInsertRowid: Number(result.lastInsertRowid ?? 0),
          changes: Number(result.rowsAffected ?? 0)
        };
      }
      if (localDb) {
        const r = localDb.prepare(sql).run(...args);
        return { lastInsertRowid: Number(r.lastInsertRowid), changes: Number(r.changes) };
      }
      return { lastInsertRowid: 0, changes: 0 };
    }
  };
}

const db = { prepare };

function hashPassword(password, existingSalt) {
  const salt = existingSalt || crypto.randomBytes(16).toString('hex');
  const derived = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
  return `${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  if (stored.includes(':')) {
    const [salt, expected] = stored.split(':');
    const actual = crypto.pbkdf2Sync(password, salt, 100000, 32, 'sha256').toString('hex');
    return actual === expected;
  }
  return crypto.createHash('sha256').update(password).digest('hex') === stored;
}

async function initDb() {
  if (tursoClient) {
    for (const stmt of SCHEMA_STATEMENTS) {
      await tursoClient.execute(stmt);
    }
    for (const stmt of MIGRATION_STATEMENTS) {
      try { await tursoClient.execute(stmt); } catch (e) {}
    }
  } else if (localDb) {
    localDb.exec(SCHEMA_STATEMENTS.join(';\n') + ';');
    for (const stmt of MIGRATION_STATEMENTS) {
      try { localDb.exec(stmt); } catch (e) {}
    }
  }

  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'Admin@12345';
  const hashed = hashPassword(adminPass);

  const existingAdmin = await db.prepare('SELECT * FROM admins WHERE username = ?').get(adminUser);
  if (existingAdmin) {
    await db.prepare('UPDATE admins SET password_hash = ? WHERE username = ?').run(hashed, adminUser);
  } else {
    await db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(adminUser, hashed);
  }

  console.log('-------------------------------------------');
  console.log(`🔐 ADMIN READY -> Username: ${adminUser} | Password: ${adminPass}`);
  console.log('-------------------------------------------');

  const catCount = await db.prepare('SELECT COUNT(*) AS c FROM categories').get();
  if (catCount && catCount.c === 0) {
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Burgers');
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Pizza');
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Beverages');
  }
}

// ==========================================
// 2. SESSION & RATE LIMITING
// ==========================================
const adminSessions = new Map();
const userSessions = new Map();
const loginAttempts = new Map();

function newAdminSession() {
  const token = crypto.randomBytes(24).toString('hex');
  adminSessions.set(token, Date.now() + 24 * 60 * 60 * 1000);
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

function newUserSession(userId) {
  const token = crypto.randomBytes(24).toString('hex');
  userSessions.set(token, { userId, expiry: Date.now() + 30 * 24 * 60 * 60 * 1000 });
  return token;
}
function getUserIdFromRequest(req) {
  const auth = req.headers['authorization'] || '';
  const token = auth.replace('Bearer ', '').trim();
  const session = userSessions.get(token);
  if (!session || Date.now() > session.expiry) return null;
  return session.userId;
}

function clientKey(req, id) {
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown').split(',')[0].trim();
  return `${ip}:${id}`;
}
function isRateLimited(key, max = 8) {
  const entry = loginAttempts.get(key);
  if (!entry) return false;
  if (Date.now() - entry.firstAttempt > 15 * 60 * 1000) {
    loginAttempts.delete(key);
    return false;
  }
  return entry.count >= max;
}
function recordFailedAttempt(key) {
  const entry = loginAttempts.get(key);
  if (!entry || Date.now() - entry.firstAttempt > 15 * 60 * 1000) {
    loginAttempts.set(key, { count: 1, firstAttempt: Date.now() });
  } else {
    entry.count++;
  }
}

// ==========================================
// 3. HTTP HELPERS & STATIC SERVING
// ==========================================
function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => { data += chunk; });
    req.on('end', () => {
      if (!data) return resolve({});
      try { resolve(JSON.parse(data)); } catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

function serveStatic(req, res, urlPath) {
  let relativePath = urlPath === '/' ? '/index.html' : urlPath;
  let targetPath = path.join(PUBLIC_DIR, relativePath);
  if (!fs.existsSync(targetPath)) {
    let rootRelative = relativePath.replace(/^\/admin\//, '/');
    targetPath = path.join(ROOT_DIR, rootRelative);
  }

  const baseName = path.basename(targetPath);
  if (baseName.startsWith('.') || baseName.endsWith('.js') || baseName.endsWith('.db') || baseName.endsWith('.json') || baseName === 'README.md') {
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    return res.end('Not found');
  }

  fs.readFile(targetPath, (err, content) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      return res.end('Not found');
    }
    const ext = path.extname(targetPath);
    const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.svg': 'image/svg+xml' };
    res.writeHead(200, { 'Content-Type': types[ext] || 'application/octet-stream' });
    res.end(content);
  });
}

// ==========================================
// 4. API ROUTING
// ==========================================
async function handleApi(req, res, urlPath) {
  const method = req.method;

  // Admin Auth
  if (urlPath === '/api/admin/login' && method === 'POST') {
    const { username, password } = await readBody(req);
    const key = clientKey(req, 'admin:' + username);
    if (isRateLimited(key)) return sendJson(res, 429, { error: 'Too many attempts. Try later.' });

    const admin = await db.prepare('SELECT * FROM admins WHERE username = ?').get(username);
    if (!admin || !verifyPassword(password || '', admin.password_hash)) {
      recordFailedAttempt(key);
      return sendJson(res, 401, { error: 'Invalid credentials' });
    }
    const token = newAdminSession();
    return sendJson(res, 200, { token, username: admin.username });
  }

  if (urlPath === '/api/admin/logout' && method === 'POST') {
    const auth = req.headers['authorization'] || '';
    adminSessions.delete(auth.replace('Bearer ', '').trim());
    return sendJson(res, 200, { success: true });
  }

  // Protected Admin Routes Check
  if (urlPath.startsWith('/api/admin') || ['/api/users', '/api/orders', '/api/categories', '/api/items', '/api/banners'].some(p => urlPath.startsWith(p))) {
    const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
    if (!isValidAdminSession(token)) return sendJson(res, 401, { error: 'Unauthorized' });
  }

  // Users
  if (urlPath === '/api/users' && method === 'GET') {
    const users = await db.prepare('SELECT id, name, username, mobile, address, created_at FROM users').all();
    return sendJson(res, 200, users);
  }

  // Orders
  if (urlPath === '/api/orders' && method === 'GET') {
    const orders = await db.prepare(`SELECT o.*, u.name as customer_name, u.mobile FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.created_at DESC`).all();
    return sendJson(res, 200, orders.map(o => ({ ...o, items: JSON.parse(o.items_json || '[]') })));
  }
  const orderStatusMatch = urlPath.match(/^\/api\/orders\/(\d+)\/status$/);
  if (orderStatusMatch && method === 'PATCH') {
    const { order_status } = await readBody(req);
    await db.prepare("UPDATE orders SET order_status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?").run(order_status, orderStatusMatch[1]);
    return sendJson(res, 200, { success: true });
  }

  // Categories
  if (urlPath === '/api/categories' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM categories ORDER BY name').all());
  }
  if (urlPath === '/api/categories' && method === 'POST') {
    const { name } = await readBody(req);
    const info = await db.prepare('INSERT INTO categories (name) VALUES (?)').run(name.trim());
    return sendJson(res, 201, { id: Number(info.lastInsertRowid), name: name.trim() });
  }

  // Items
  if (urlPath === '/api/items' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT items.*, categories.name as category_name FROM items LEFT JOIN categories ON categories.id = items.category_id').all());
  }
  if (urlPath === '/api/items' && method === 'POST') {
    const { name, price, category_id, image_url, description } = await readBody(req);
    const info = await db.prepare(`INSERT INTO items (name, price, category_id, image_url, description) VALUES (?, ?, ?, ?, ?)`).run(name, price, category_id || null, image_url || '', description || '');
    return sendJson(res, 201, { id: Number(info.lastInsertRowid) });
  }
  const itemMatch = urlPath.match(/^\/api\/items\/(\d+)$/);
  if (itemMatch && method === 'DELETE') {
    await db.prepare('DELETE FROM items WHERE id = ?').run(itemMatch[1]);
    return sendJson(res, 200, { success: true });
  }

  // Banners
  if (urlPath === '/api/banners' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM banners ORDER BY sort_order').all());
  }
  if (urlPath === '/api/banners' && method === 'POST') {
    const { title, image_url } = await readBody(req);
    const info = await db.prepare(`INSERT INTO banners (title, image_url) VALUES (?, ?)`).run(title || '', image_url || '');
    return sendJson(res, 201, { id: Number(info.lastInsertRowid) });
  }

  // Public Routes
  if (urlPath === '/api/public/login' && method === 'POST') {
    const { mobile, password } = await readBody(req);
    const user = await db.prepare('SELECT * FROM users WHERE mobile = ?').get(mobile);
    if (!user || !verifyPassword(password || '', user.password_hash)) {
      return sendJson(res, 401, { error: 'Invalid mobile or password' });
    }
    const token = newUserSession(user.id);
    return sendJson(res, 200, { id: user.id, name: user.name, mobile: user.mobile, token });
  }
  if (urlPath === '/api/public/menu' && method === 'GET') {
    return sendJson(res, 200, await db.prepare('SELECT * FROM items WHERE available = 1').all());
  }

  return sendJson(res, 404, { error: 'Not found' });
}

// ==========================================
// 5. START SERVER
// ==========================================
const server = http.createServer(async (req, res) => {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Access-Control-Allow-Methods': 'GET,POST,PUT,PATCH,DELETE,OPTIONS'
    });
    return res.end();
  }
  if (parsedUrl.pathname.startsWith('/api/')) {
    try {
      await handleApi(req, res, parsedUrl.pathname);
    } catch (e) {
      console.error(e);
      sendJson(res, 500, { error: 'Internal Error' });
    }
    return;
  }
  serveStatic(req, res, parsedUrl.pathname);
});

initDb().then(() => {
  server.listen(PORT, () => {
    console.log(`🚀 FastBites running on port ${PORT}`);
  });
}).catch(err => {
  console.error('Database initialization error:', err);
});