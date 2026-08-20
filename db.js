// db.js — Database layer
const crypto = require('crypto');
const path = require('path');

const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

let tursoClient = null;
let localDb = null;

if (TURSO_URL && TURSO_TOKEN) {
  const { createClient } = require('@libsql/client');
  tursoClient = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
  console.log('📡 Using Turso cloud database.');
} else {
  const { DatabaseSync } = require('node:sqlite');
  const dbPath = path.join(__dirname, 'fastbites.db');
  localDb = new DatabaseSync(dbPath);
  console.log('💾 Using local SQLite file.');
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
      return localDb.prepare(sql).get(...args);
    },
    async all(...args) {
      if (tursoClient) {
        const result = await tursoClient.execute({ sql, args });
        return result.rows.map(r => ({ ...r }));
      }
      return localDb.prepare(sql).all(...args);
    },
    async run(...args) {
      if (tursoClient) {
        const result = await tursoClient.execute({ sql, args });
        return {
          lastInsertRowid: Number(result.lastInsertRowid ?? 0),
          changes: Number(result.rowsAffected ?? 0)
        };
      }
      const r = localDb.prepare(sql).run(...args);
      return { lastInsertRowid: Number(r.lastInsertRowid), changes: Number(r.changes) };
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

function hash(pw) {
  return hashPassword(pw);
}

async function initDb() {
  if (tursoClient) {
    for (const stmt of SCHEMA_STATEMENTS) {
      await tursoClient.execute(stmt);
    }
    for (const stmt of MIGRATION_STATEMENTS) {
      try { await tursoClient.execute(stmt); } catch (e) {}
    }
  } else {
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

  console.log(`Admin Active -> User: ${adminUser} | Pass: ${adminPass}`);

  const catCountRow = await db.prepare('SELECT COUNT(*) AS c FROM categories').get();
  if (catCountRow && catCountRow.c === 0) {
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Burgers');
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Pizza');
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Beverages');
  }
}

module.exports = { db, hash, hashPassword, verifyPassword, initDb };
