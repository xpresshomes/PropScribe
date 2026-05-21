const Database = require('better-sqlite3')
const path = require('path')
const fs = require('fs')

// Railway persistent storage: use /data volume if available, else local data/
// Set DATA_DIR env variable in Railway to /data for persistence across deploys
const dataDir = process.env.DATA_DIR
  || (process.env.NODE_ENV === 'production' ? '/data' : path.join(__dirname, 'data'))

// Create data directory if it doesn't exist
try {
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true })
} catch (e) {
  console.error('Could not create data directory:', e.message)
}

const dbPath = path.join(dataDir, 'propscribe.db')
console.log('Database path:', dbPath)

const db = new Database(dbPath)

// WAL mode — better concurrent read performance
db.pragma('journal_mode = WAL')
db.pragma('foreign_keys = ON')

// ── Tables ─────────────────────────────────────────────────────────────────────
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    email       TEXT    UNIQUE NOT NULL,
    password    TEXT    NOT NULL,
    name        TEXT    NOT NULL DEFAULT '',
    plan        TEXT    NOT NULL DEFAULT 'free',
    is_admin    INTEGER NOT NULL DEFAULT 0,
    created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    last_login  TEXT
  );

  CREATE TABLE IF NOT EXISTS generations (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id),
    property     TEXT,
    location     TEXT,
    platforms    TEXT,
    tokens_used  INTEGER DEFAULT 0,
    created_at   TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS plans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT UNIQUE NOT NULL,
    monthly_limit INTEGER NOT NULL,
    price_naira   INTEGER NOT NULL,
    description   TEXT
  );
`)

// ── Seed Plans ─────────────────────────────────────────────────────────────────
const insertPlan = db.prepare(
  'INSERT OR IGNORE INTO plans (name, monthly_limit, price_naira, description) VALUES (?, ?, ?, ?)'
)
insertPlan.run('free',    5,    0,     '5 generations/month — try before you buy')
insertPlan.run('starter', 50,  5000,  '50 generations/month — perfect for small agencies')
insertPlan.run('pro',     200, 12000, '200 generations/month — serious agents')
insertPlan.run('agency',  999, 25000, 'Unlimited — agencies and teams')

// ── Prepared Statements ────────────────────────────────────────────────────────
const getUser        = db.prepare('SELECT * FROM users WHERE email = ?')
const getUserById    = db.prepare('SELECT * FROM users WHERE id = ?')
const createUser     = db.prepare('INSERT INTO users (email, password, name, plan, is_admin) VALUES (?, ?, ?, ?, ?)')
const updateLastLogin = db.prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?")
const updatePlan     = db.prepare('UPDATE users SET plan = ? WHERE id = ?')

const countMonthlyGenerations = db.prepare(`
  SELECT COUNT(*) as count FROM generations
  WHERE user_id = ? AND created_at >= date('now', 'start of month')
`)

const logGeneration = db.prepare(
  'INSERT INTO generations (user_id, property, location, platforms, tokens_used) VALUES (?, ?, ?, ?, ?)'
)

const getPlan = db.prepare('SELECT * FROM plans WHERE name = ?')

const getAllUsers = db.prepare(`
  SELECT u.id, u.email, u.name, u.plan, u.created_at, u.last_login,
    (SELECT COUNT(*) FROM generations g WHERE g.user_id = u.id) as total_gens
  FROM users u ORDER BY u.created_at DESC
`)

const getStats = db.prepare(`
  SELECT
    (SELECT COUNT(*) FROM users) as total_users,
    (SELECT COUNT(*) FROM users WHERE plan != 'free') as paid_users,
    (SELECT COUNT(*) FROM generations) as total_generations,
    (SELECT COUNT(*) FROM generations WHERE created_at >= date('now', '-7 days')) as weekly_generations
`)

module.exports = {
  db,
  getUser, getUserById, createUser, updateLastLogin, updatePlan,
  countMonthlyGenerations, logGeneration, getPlan,
  getAllUsers, getStats
}
