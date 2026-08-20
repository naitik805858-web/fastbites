// db.js — Database layer.
// Uses Turso (cloud SQLite, free tier, DATA PERSISTS FOREVER across redeploys) when
// TURSO_DATABASE_URL and TURSO_AUTH_TOKEN environment variables are set — this is what
// you should configure on Render for a real, permanent website.
// Falls back to a local file-based SQLite database (Node's built-in node:sqlite) when
// those env vars are absent — this is only for quick local testing (e.g. in Termux),
// where data does NOT need to survive redeploys.
const crypto = require('crypto');
const path = require('path');

const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

let tursoClient = null;
let localDb = null;

if (TURSO_URL && TURSO_TOKEN) {
  const { createClient } = require('@libsql/client');
  tursoClient = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });
  console.log('📡 Using Turso cloud database (data will persist across deploys).');
} else {
  const { DatabaseSync } = require('node:sqlite');
  const dbPath = path.join(__dirname, 'data', 'fastbites.db');
  localDb = new DatabaseSync(dbPath);
  console.log('💾 Using local SQLite file (fine for local testing only — set TURSO_DATABASE_URL + TURSO_AUTH_TOKEN on Render for a permanent database).');
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

// Adds columns to an existing (older) database that was created before this update.
// Safe to run every time — ignores "duplicate column" errors.
const MIGRATION_STATEMENTS = [
  `ALTER TABLE items ADD COLUMN long_description TEXT`,
  `ALTER TABLE items ADD COLUMN rating REAL DEFAULT 4.5`,
  `ALTER TABLE items ADD COLUMN rating_count TEXT DEFAULT ''`,
  `ALTER TABLE items ADD COLUMN prep_time TEXT DEFAULT '20 mins'`
];

// ---------- Statement wrapper: same .get()/.all()/.run() interface for both backends ----------
// All three are ASYNC now (they return Promises) since Turso is a network database.
// Callers in server.js must `await` these.
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

function generateRandomPassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  let pw = '';
  const bytes = crypto.randomBytes(12);
  for (let i = 0; i < 12; i++) pw += chars[bytes[i] % chars.length];
  return pw;
}

// Runs schema creation + migrations + seeding. MUST be awaited once before the server starts.
async function initDb() {
  if (tursoClient) {
    for (const stmt of SCHEMA_STATEMENTS) {
      await tursoClient.execute(stmt);
    }
    for (const stmt of MIGRATION_STATEMENTS) {
      try { await tursoClient.execute(stmt); } catch (e) { /* column already exists — fine */ }
    }
  } else {
    localDb.exec(SCHEMA_STATEMENTS.join(';\n') + ';');
    for (const stmt of MIGRATION_STATEMENTS) {
      try { localDb.exec(stmt); } catch (e) { /* column already exists — fine */ }
    }
  }

  const adminCountRow = await db.prepare('SELECT COUNT(*) AS c FROM admins').get();
  if (adminCountRow.c === 0) {
    const generatedPassword = generateRandomPassword();
    await db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)')
      .run('admin', hashPassword(generatedPassword));
    console.log('');
    console.log('════════════════════════════════════════════════════');
    console.log('  ADMIN LOGIN CREATED — SAVE THIS NOW, SHOWN ONCE:');
    console.log('  Username: admin');
    console.log(`  Password: ${generatedPassword}`);
    console.log('════════════════════════════════════════════════════');
    console.log('  Forgot it later? Run: node change-admin-password.js yournewpassword');
    console.log('');
  }

  const catCountRow = await db.prepare('SELECT COUNT(*) AS c FROM categories').get();
  if (catCountRow.c === 0) {
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Burgers');
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Pizza');
    await db.prepare('INSERT INTO categories (name) VALUES (?)').run('Beverages');
  }
}

module.exports = { db, hash, hashPassword, verifyPassword, initDb };
