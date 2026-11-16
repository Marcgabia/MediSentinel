import fs from 'fs';
import path from 'path';
import mysql from 'mysql2/promise';
import { fileURLToPath, pathToFileURL } from 'url';
import { sequelize, databaseName, connectionOptions } from '../config/database.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const MIGRATIONS_DIR = path.join(__dirname, '..', 'migrations');

const assertSafeDbName = (name) => {
  if (!/^[A-Za-z0-9_]+$/.test(name)) throw new Error(`Unsafe database name: ${name}`);
};

/** Create the database if it does not exist (never drops anything). */
export const ensureDatabase = async () => {
  assertSafeDbName(databaseName);
  const conn = await mysql.createConnection({ ...connectionOptions });
  try {
    await conn.query(`CREATE DATABASE IF NOT EXISTS \`${databaseName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  } finally {
    await conn.end();
  }
};

/** Drop and recreate the database. Refuses to run unless the name ends with _test. */
export const resetTestDatabase = async () => {
  if (!databaseName.endsWith('_test')) throw new Error(`Refusing to reset non-test database "${databaseName}".`);
  assertSafeDbName(databaseName);
  const conn = await mysql.createConnection({ ...connectionOptions });
  try {
    await conn.query(`DROP DATABASE IF EXISTS \`${databaseName}\``);
    await conn.query(`CREATE DATABASE \`${databaseName}\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`);
  } finally {
    await conn.end();
  }
};

const listMigrationFiles = () => fs.readdirSync(MIGRATIONS_DIR).filter((f) => /^\d+.*\.js$/.test(f)).sort();

/** Apply pending migrations in order. Each migration exports `up({ sequelize, queryInterface })`. */
export const runMigrations = async ({ log = console.log } = {}) => {
  await ensureDatabase();
  await sequelize.authenticate();
  await sequelize.query(`CREATE TABLE IF NOT EXISTS schema_migrations (
    name VARCHAR(190) NOT NULL PRIMARY KEY,
    appliedAt DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4`);

  const [rows] = await sequelize.query('SELECT name FROM schema_migrations');
  const applied = new Set(rows.map((r) => r.name));
  const pending = listMigrationFiles().filter((f) => !applied.has(f));

  for (const file of pending) {
    const mod = await import(pathToFileURL(path.join(MIGRATIONS_DIR, file)).href);
    log(`→ applying migration ${file}`);
    await mod.up({ sequelize, queryInterface: sequelize.getQueryInterface() });
    await sequelize.query('INSERT INTO schema_migrations (name) VALUES (?)', { replacements: [file] });
  }
  if (!pending.length) log('✓ database schema is up to date');
  return pending;
};
