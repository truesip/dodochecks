'use strict';

const fs = require('node:fs');
const path = require('node:path');

let sqliteDb;
let sqliteStmts;

let mysqlPool;
let mysqlInitPromise;

function env(name) {
  const v = process.env[name];
  if (!v) return null;
  const s = String(v).trim();
  return s ? s : null;
}

function getDatabaseUrl() {
  return env('DATABASE_URL') || env('MYSQL_URL') || env('MYSQL_DATABASE_URL');
}

function shouldUseMysql() {
  const url = getDatabaseUrl();
  if (!url) return false;
  return url.startsWith('mysql://') || url.startsWith('mariadb://');
}

function ensureDir(dirPath) {
  fs.mkdirSync(dirPath, { recursive: true });
}

function getSqliteDbPath() {
  // Example: ./data/dodo-checks.sqlite
  const fromEnv = env('SQLITE_DB_PATH');
  if (fromEnv) return fromEnv;

  return path.join(process.cwd(), 'data', 'dodo-checks.sqlite');
}

function ensureSqliteColumn(database, tableName, columnName, columnSql) {
  const rows = database.prepare(`PRAGMA table_info('${tableName}')`).all();
  const has = rows.some((r) => String(r?.name || '') === columnName);
  if (has) return;

  database.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${columnSql};`);
}

function initSqliteSchema(database) {
  database.exec(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      payload_json TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS audit_events_user_id_created_at_idx
      ON audit_events(user_id, created_at DESC);

    -- Per-user compliance profile (CIP / KYC data).
    -- Note: avoid storing raw SSNs; store encrypted values + last4.
    CREATE TABLE IF NOT EXISTS user_compliance (
      user_id INTEGER PRIMARY KEY,
      full_name TEXT,
      email TEXT,
      phone TEXT,
      date_of_birth TEXT,
      ssn_last4 TEXT,
      ssn_ciphertext TEXT,
      address_line1 TEXT,
      address_line2 TEXT,
      city TEXT,
      state TEXT,
      zip TEXT,
      status TEXT NOT NULL DEFAULT 'draft',
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      updated_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );


    -- Compliance documents uploaded by the user.
    CREATE TABLE IF NOT EXISTS user_compliance_documents (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      kind TEXT NOT NULL,
      file_id TEXT NOT NULL,
      filename TEXT,
      mime_type TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS user_compliance_documents_user_id_created_at_idx
      ON user_compliance_documents(user_id, created_at DESC);

    -- Exports created by the user.
    CREATE TABLE IF NOT EXISTS user_exports (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      export_id TEXT NOT NULL,
      category TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE UNIQUE INDEX IF NOT EXISTS user_exports_export_id_unique
      ON user_exports(export_id);

    CREATE INDEX IF NOT EXISTS user_exports_user_id_created_at_idx
      ON user_exports(user_id, created_at DESC);
  `);

}

function prepareSqliteStatements(database) {
  return {
    insertUser: database.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)'),
    getUserByEmail: database.prepare(
      'SELECT id, email, password_hash, created_at FROM users WHERE email = ?'
    ),
    getUserById: database.prepare('SELECT id, email, password_hash, created_at FROM users WHERE id = ?'),
    insertAuditEvent: database.prepare(
      'INSERT INTO audit_events (user_id, type, payload_json) VALUES (?, ?, ?)'
    ),
    listRecentEventsForUser: database.prepare(
      'SELECT id, type, payload_json, created_at FROM audit_events WHERE user_id = ? ORDER BY id DESC LIMIT ?'
    ),

    // Compliance
    upsertUserCompliance: database.prepare(`
      INSERT INTO user_compliance (
        user_id, full_name, email, phone, date_of_birth,
        ssn_last4, ssn_ciphertext,
        address_line1, address_line2, city, state, zip,
        status, updated_at
      ) VALUES (
        ?, ?, ?, ?, ?,
        ?, ?,
        ?, ?, ?, ?, ?,
        ?, datetime('now')
      )
      ON CONFLICT(user_id) DO UPDATE SET
        full_name = excluded.full_name,
        email = excluded.email,
        phone = excluded.phone,
        date_of_birth = excluded.date_of_birth,
        ssn_last4 = excluded.ssn_last4,
        ssn_ciphertext = excluded.ssn_ciphertext,
        address_line1 = excluded.address_line1,
        address_line2 = excluded.address_line2,
        city = excluded.city,
        state = excluded.state,
        zip = excluded.zip,
        status = excluded.status,
        updated_at = datetime('now')
    `),
    getUserCompliance: database.prepare(
      `SELECT user_id, full_name, email, phone, date_of_birth, ssn_last4, ssn_ciphertext,
              address_line1, address_line2, city, state, zip, status, created_at, updated_at
       FROM user_compliance WHERE user_id = ?`
    ),

    // Compliance docs
    insertUserComplianceDocument: database.prepare(
      'INSERT INTO user_compliance_documents (user_id, kind, file_id, filename, mime_type) VALUES (?, ?, ?, ?, ?)'
    ),
    listUserComplianceDocuments: database.prepare(
      'SELECT id, user_id, kind, file_id, filename, mime_type, created_at FROM user_compliance_documents WHERE user_id = ? ORDER BY id DESC LIMIT ?'
    ),

    // User exports
    insertUserExport: database.prepare(
      'INSERT INTO user_exports (user_id, export_id, category) VALUES (?, ?, ?)'
    ),
    listUserExports: database.prepare(
      'SELECT id, user_id, export_id, category, created_at FROM user_exports WHERE user_id = ? ORDER BY id DESC LIMIT ?'
    ),
  };
}

function getSqliteDb() {
  if (sqliteDb) return sqliteDb;

  // Lazy import so older Node versions (or prod MySQL deployments) don't require node:sqlite.
  // eslint-disable-next-line global-require
  const { DatabaseSync } = require('node:sqlite');

  const dbPath = getSqliteDbPath();
  ensureDir(path.dirname(dbPath));

  sqliteDb = new DatabaseSync(dbPath);
  initSqliteSchema(sqliteDb);
  sqliteStmts = prepareSqliteStatements(sqliteDb);

  return sqliteDb;
}

function mysqlSslFromUrl(urlObj) {
  const rawMode =
    urlObj.searchParams.get('ssl-mode') ||
    urlObj.searchParams.get('sslmode') ||
    urlObj.searchParams.get('ssl');

  if (!rawMode) return undefined;

  const mode = String(rawMode).trim().toUpperCase();
  if (!mode || mode === 'DISABLED' || mode === 'OFF' || mode === '0' || mode === 'FALSE') return undefined;

  // Prefer a CA cert (optional) if provided.
  const ca = env('MYSQL_SSL_CA') || env('DATABASE_SSL_CA');
  if (ca) {
    return {
      ca,
      rejectUnauthorized: true,
    };
  }

  // If ssl-mode=REQUIRED is set (DigitalOcean typically uses this), use TLS without CA validation.
  // This still encrypts traffic, but does not verify the server cert chain.
  return {
    rejectUnauthorized: false,
  };
}

function parseMysqlUrl(databaseUrl) {
  const urlObj = new URL(databaseUrl);

  const database = String(urlObj.pathname || '').replace(/^\//, '');
  if (!database) {
    throw new Error('DATABASE_URL must include a database name (e.g. /defaultdb)');
  }

  const port = urlObj.port ? Number(urlObj.port) : 3306;

  return {
    host: urlObj.hostname,
    port: Number.isFinite(port) ? port : 3306,
    // URL.username / URL.password are already decoded by the WHATWG URL parser.
    // Avoid decodeURIComponent here so passwords containing "%" don't throw.
    user: urlObj.username || '',
    password: urlObj.password || '',
    database,
    ssl: mysqlSslFromUrl(urlObj),
  };
}

async function initMysqlSchema(pool) {
  await pool.execute(`
    CREATE TABLE IF NOT EXISTS users (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      email VARCHAR(255) NOT NULL,
      password_hash VARCHAR(255) NOT NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY users_email_unique (email)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS audit_events (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      type VARCHAR(255) NOT NULL,
      payload_json TEXT,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY audit_events_user_id_created_at_idx (user_id, created_at),
      CONSTRAINT audit_events_user_fk FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS user_compliance (
      user_id BIGINT UNSIGNED NOT NULL,
      full_name VARCHAR(255) NULL,
      email VARCHAR(255) NULL,
      phone VARCHAR(64) NULL,
      date_of_birth VARCHAR(16) NULL,
      ssn_last4 VARCHAR(4) NULL,
      ssn_ciphertext TEXT NULL,
      address_line1 VARCHAR(255) NULL,
      address_line2 VARCHAR(255) NULL,
      city VARCHAR(128) NULL,
      state VARCHAR(64) NULL,
      zip VARCHAR(32) NULL,
      status VARCHAR(32) NOT NULL DEFAULT 'draft',
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
      PRIMARY KEY (user_id),
      CONSTRAINT user_compliance_user_fk FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);


  await pool.execute(`
    CREATE TABLE IF NOT EXISTS user_compliance_documents (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      kind VARCHAR(64) NOT NULL,
      file_id VARCHAR(128) NOT NULL,
      filename VARCHAR(255) NULL,
      mime_type VARCHAR(128) NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      KEY user_compliance_documents_user_id_created_at_idx (user_id, created_at),
      CONSTRAINT user_compliance_documents_user_fk FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);

  await pool.execute(`
    CREATE TABLE IF NOT EXISTS user_exports (
      id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
      user_id BIGINT UNSIGNED NOT NULL,
      export_id VARCHAR(128) NOT NULL,
      category VARCHAR(128) NULL,
      created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
      PRIMARY KEY (id),
      UNIQUE KEY user_exports_export_id_unique (export_id),
      KEY user_exports_user_id_created_at_idx (user_id, created_at),
      CONSTRAINT user_exports_user_fk FOREIGN KEY (user_id)
        REFERENCES users(id)
        ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
  `);
}

async function getMysqlPool() {
  if (mysqlPool) return mysqlPool;
  if (mysqlInitPromise) return mysqlInitPromise;

  const databaseUrl = getDatabaseUrl();
  if (!databaseUrl) {
    throw new Error('DATABASE_URL is required for MySQL');
  }

  mysqlInitPromise = (async () => {
    // eslint-disable-next-line global-require
    const mysql = require('mysql2/promise');

    const cfg = parseMysqlUrl(databaseUrl);

    const pool = mysql.createPool({
      host: cfg.host,
      port: cfg.port,
      user: cfg.user,
      password: cfg.password,
      database: cfg.database,
      ssl: cfg.ssl,
      waitForConnections: true,
      connectionLimit: Number(env('MYSQL_CONNECTION_LIMIT') || 10),
      dateStrings: true,
    });

    await initMysqlSchema(pool);
    mysqlPool = pool;
    return pool;
  })();

  return mysqlInitPromise;
}

async function getDb() {
  if (shouldUseMysql()) {
    return getMysqlPool();
  }

  return getSqliteDb();
}

async function createUser({ email, passwordHash }) {
  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [result] = await pool.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', [
      email,
      passwordHash,
    ]);
    return Number(result.insertId);
  }

  getSqliteDb();
  const info = sqliteStmts.insertUser.run(email, passwordHash);
  return Number(info.lastInsertRowid);
}

async function getUserByEmail(email) {
  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT id, email, password_hash, created_at FROM users WHERE email = ? LIMIT 1',
      [email]
    );
    return rows && rows[0] ? rows[0] : null;
  }

  getSqliteDb();
  return sqliteStmts.getUserByEmail.get(email) || null;
}

async function getUserById(id) {
  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      'SELECT id, email, password_hash, created_at FROM users WHERE id = ? LIMIT 1',
      [id]
    );
    return rows && rows[0] ? rows[0] : null;
  }

  getSqliteDb();
  return sqliteStmts.getUserById.get(id) || null;
}

async function createAuditEvent({ userId, type, payload }) {
  const payloadJson = payload == null ? null : JSON.stringify(payload);

  try {
    if (shouldUseMysql()) {
      const pool = await getMysqlPool();
      await pool.execute('INSERT INTO audit_events (user_id, type, payload_json) VALUES (?, ?, ?)', [
        userId,
        type,
        payloadJson,
      ]);
      return;
    }

    getSqliteDb();
    sqliteStmts.insertAuditEvent.run(userId, type, payloadJson);
  } catch (err) {
    // Audit events should never break core flows.
    if (env('APP_DEBUG')) {
      // eslint-disable-next-line no-console
      console.warn('[audit] failed to write event', { type, error: String(err?.message || err) });
    }
  }
}

async function upsertUserCompliance({
  userId,
  fullName,
  email,
  phone,
  dateOfBirth,
  ssnLast4,
  ssnCiphertext,
  addressLine1,
  addressLine2,
  city,
  state,
  zip,
  status,
}) {
  const safeStatus = String(status || 'draft').trim() || 'draft';

  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    await pool.execute(
      `INSERT INTO user_compliance (
        user_id, full_name, email, phone, date_of_birth,
        ssn_last4, ssn_ciphertext,
        address_line1, address_line2, city, state, zip,
        status
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON DUPLICATE KEY UPDATE
        full_name = VALUES(full_name),
        email = VALUES(email),
        phone = VALUES(phone),
        date_of_birth = VALUES(date_of_birth),
        ssn_last4 = VALUES(ssn_last4),
        ssn_ciphertext = VALUES(ssn_ciphertext),
        address_line1 = VALUES(address_line1),
        address_line2 = VALUES(address_line2),
        city = VALUES(city),
        state = VALUES(state),
        zip = VALUES(zip),
        status = VALUES(status)`,
      [
        userId,
        fullName || null,
        email || null,
        phone || null,
        dateOfBirth || null,
        ssnLast4 || null,
        ssnCiphertext || null,
        addressLine1 || null,
        addressLine2 || null,
        city || null,
        state || null,
        zip || null,
        safeStatus,
      ]
    );
    return;
  }

  getSqliteDb();
  sqliteStmts.upsertUserCompliance.run(
    userId,
    fullName || null,
    email || null,
    phone || null,
    dateOfBirth || null,
    ssnLast4 || null,
    ssnCiphertext || null,
    addressLine1 || null,
    addressLine2 || null,
    city || null,
    state || null,
    zip || null,
    safeStatus
  );
}

async function getUserCompliance(userId) {
  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      `SELECT user_id, full_name, email, phone, date_of_birth, ssn_last4, ssn_ciphertext,
              address_line1, address_line2, city, state, zip, status, created_at, updated_at
       FROM user_compliance WHERE user_id = ? LIMIT 1`,
      [userId]
    );
    return rows && rows[0] ? rows[0] : null;
  }

  getSqliteDb();
  return sqliteStmts.getUserCompliance.get(userId) || null;
}


async function addUserComplianceDocument({ userId, kind, fileId, filename, mimeType }) {
  if (!fileId) throw new Error('fileId is required');
  const k = String(kind || '').trim();
  if (!k) throw new Error('kind is required');

  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO user_compliance_documents (user_id, kind, file_id, filename, mime_type) VALUES (?, ?, ?, ?, ?)',
      [userId, k, fileId, filename || null, mimeType || null]
    );
    return;
  }

  getSqliteDb();
  sqliteStmts.insertUserComplianceDocument.run(userId, k, fileId, filename || null, mimeType || null);
}

async function listUserComplianceDocuments(userId, limit = 50) {
  const lim = Number.isInteger(Number(limit)) ? Number(limit) : 50;
  const safeLimit = Math.max(1, Math.min(200, lim));

  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      `SELECT id, user_id, kind, file_id, filename, mime_type, created_at
       FROM user_compliance_documents WHERE user_id = ?
       ORDER BY id DESC LIMIT ${safeLimit}`,
      [userId]
    );
    return rows || [];
  }

  getSqliteDb();
  return sqliteStmts.listUserComplianceDocuments.all(userId, safeLimit);
}

async function addUserExport({ userId, exportId, category }) {
  if (!exportId) throw new Error('exportId is required');

  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    await pool.execute(
      'INSERT INTO user_exports (user_id, export_id, category) VALUES (?, ?, ?)',
      [userId, exportId, category || null]
    );
    return;
  }

  getSqliteDb();
  sqliteStmts.insertUserExport.run(userId, exportId, category || null);
}

async function listUserExports(userId, limit = 50) {
  const lim = Number.isInteger(Number(limit)) ? Number(limit) : 50;
  const safeLimit = Math.max(1, Math.min(200, lim));

  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      `SELECT id, user_id, export_id, category, created_at
       FROM user_exports WHERE user_id = ?
       ORDER BY id DESC LIMIT ${safeLimit}`,
      [userId]
    );
    return rows || [];
  }

  getSqliteDb();
  return sqliteStmts.listUserExports.all(userId, safeLimit);
}

async function listRecentEventsForUser(userId, limit = 10) {
  const lim = Number.isInteger(Number(limit)) ? Number(limit) : 10;
  const safeLimit = Math.max(1, Math.min(100, lim));

  if (shouldUseMysql()) {
    const pool = await getMysqlPool();
    const [rows] = await pool.execute(
      `SELECT id, type, payload_json, created_at FROM audit_events WHERE user_id = ? ORDER BY id DESC LIMIT ${safeLimit}`,
      [userId]
    );
    return rows || [];
  }

  getSqliteDb();
  return sqliteStmts.listRecentEventsForUser.all(userId, safeLimit);
}

module.exports = {
  getDb,
  createUser,
  getUserByEmail,
  getUserById,
  createAuditEvent,
  listRecentEventsForUser,

  // Compliance
  upsertUserCompliance,
  getUserCompliance,
  addUserComplianceDocument,
  listUserComplianceDocuments,
  addUserExport,
  listUserExports,
};
