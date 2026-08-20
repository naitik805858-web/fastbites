// db.js — FastBites Database (Turso Cloud / Local SQLite)
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const TURSO_URL = process.env.TURSO_DATABASE_URL;
const TURSO_TOKEN = process.env.TURSO_AUTH_TOKEN;

let db;

// Password Hashing (PBKDF2)
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  if (!stored) return false;
  if (!stored.includes(':')) {
    return crypto.createHash('sha256').update(password).digest('hex') === stored;
  }
  const [salt, hash] = stored.split(':');
  const verifyHash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return hash === verifyHash;
}

if (TURSO_URL && TURSO_TOKEN) {
  const { createClient } = require('@libsql/client');
  const client = createClient({ url: TURSO_URL, authToken: TURSO_TOKEN });

  db = {
    prepare(sql) {
      return {
        async get(...args) {
          const res = await client.execute({ sql, args });
          return res.rows[0] ? formatRow(res.columns, res.rows[0]) : null;
        },
        async all(...args) {
          const res = await client.execute({ sql, args });
          return res.rows.map(r => formatRow(res.columns, r));
        },
        async run(...args) {
          const res = await client.execute({ sql, args });
          return { lastInsertRowid: res.lastInsertRowid, changes: res.rowsAffected };
        }
      };
    },
    async exec(sql) {
      return await client.executeMultiple(sql);
    }
  };
} else {
  const Database = require('better-sqlite3');
  const localDb = new Database(path.join(__dirname, 'fastbites.db'));
  db = {
    prepare(sql) {
      const stmt = localDb.prepare(sql);
      return {
        async get(...args) { return stmt.get(...args); },
        async all(...args) { return stmt.all(...args); },
        async run(...args) { return stmt.run(...args); }
      };
    },
    async exec(sql) {
      return localDb.exec(sql);
    }
  };
}

function formatRow(columns, row) {
  const obj = {};
  columns.forEach((col, idx) => {
    obj[col] = row[idx];
  });
  return obj;
}

async function initDb() {
  await db.exec(`
    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password_hash TEXT
    );
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      username TEXT UNIQUE,
      mobile TEXT UNIQUE,
      address TEXT,
      password_hash TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS categories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT UNIQUE
    );
    CREATE TABLE IF NOT EXISTS items (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT,
      price REAL,
      category_id INTEGER,
      image_url TEXT,
      description TEXT,
      long_description TEXT,
      prep_time TEXT,
      rating REAL,
      available INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS banners (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT,
      image_url TEXT,
      video_url TEXT,
      sort_order INTEGER DEFAULT 0,
      active INTEGER DEFAULT 1,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS orders (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      items_json TEXT,
      total REAL,
      payment_mode TEXT,
      payment_status TEXT,
      order_status TEXT DEFAULT 'PLACED',
      delivery_address TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  const adminUser = process.env.ADMIN_USERNAME || 'admin';
  const adminPass = process.env.ADMIN_PASSWORD || 'Admin@12345';
  const hashed = hashPassword(adminPass);

  // Force update/insert admin account
  const existing = await db.prepare('SELECT * FROM admins WHERE username = ?').get(adminUser);
  if (existing) {
    await db.prepare('UPDATE admins SET password_hash = ? WHERE username = ?').run(hashed, adminUser);
  } else {
    await db.prepare('INSERT INTO admins (username, password_hash) VALUES (?, ?)').run(adminUser, hashed);
  }

  console.log(`\n=========================================`);
  console.log(`🔐 ADMIN CREDENTIALS UPDATED:`);
  console.log(`Username: ${adminUser}`);
  console.log(`Password: ${adminPass}`);
  console.log(`=========================================\n`);
}

module.exports = { db, hashPassword, verifyPassword, initDb };
