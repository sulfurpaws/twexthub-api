// The runner `npm test` uses. It brings one template database fully up to date,
// then runs every test file against a clone of it (test/helpers.mjs) so the
// files can run at the same time without truncating each other's rows. Keeping
// the preparation and the runner behind one command means a developer can run
// it directly, and CI keeps calling plain `npm test`.
import { spawn } from 'node:child_process';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';
import { loadConfig } from '../src/config.js';
import { createDb, runMigrations } from '../src/db.js';

const ROOT = path.resolve(import.meta.dirname, '..');
const TEST_DATABASE_URL =
  process.env.TWEXTHUB_TEST_DATABASE_URL ??
  'postgres://postgres:postgres@localhost:5432/twexthub_test';

const baseName = new URL(TEST_DATABASE_URL).pathname.slice(1);
const adminUrl = new URL(TEST_DATABASE_URL);
adminUrl.pathname = '/postgres';

function spawnAndWait(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const child = spawn(command, args, { stdio: 'inherit', cwd: ROOT, ...options });
    child.on('error', reject);
    child.on('close', (code) => resolve(code ?? 1));
  });
}

// Drops the clones earlier runs left behind — a crashed run never reached its
// own cleanup — and the ones this run creates. The template itself does not
// carry the `_w<pid>` suffix, so it is never touched.
async function dropClones() {
  const client = new pg.Client({ connectionString: adminUrl.toString() });
  await client.connect();
  try {
    const { rows } = await client.query('SELECT datname FROM pg_database');
    const prefix = `${baseName}_w`;
    for (const { datname } of rows.filter((row) => row.datname.startsWith(prefix))) {
      await client.query(`DROP DATABASE IF EXISTS "${datname}" WITH (FORCE)`);
    }
  } finally {
    await client.end();
  }
}

// The template is the database a single file run would use, brought fully up to
// date once. Every clone copies its `_prisma_migrations` history, so the
// per-file boot has nothing left to apply.
async function migrateTemplate() {
  const config = loadConfig();
  config.database.url = TEST_DATABASE_URL;
  const db = createDb(config);
  try {
    await runMigrations(db, config);
  } finally {
    await db.$disconnect();
  }
}

// Enough workers to cover the database- and CPU-bound files without so many
// sandbox builds at once that they starve each other. Capped at eight: beyond
// that the clones mostly queue, and the longest single file is a floor the
// runner cannot beat. A four-core CI runner still gets four.
function concurrency() {
  const requested = Number(process.env.TWEXTHUB_TEST_CONCURRENCY);
  if (Number.isInteger(requested) && requested > 0) return requested;
  return Math.min(8, Math.max(2, os.availableParallelism()));
}

// The preflight runs on its own so a missing database is still one clear
// message instead of two hundred, before the runner spawns.
const preflight = await spawnAndWait(process.execPath, ['test/preflight.mjs']);
if (preflight !== 0) process.exit(preflight);

await dropClones();
await migrateTemplate();

const limit = concurrency();
// A download records its event with a fire-and-forgotten insert (metrics must
// not hold up the download). Under Node's runner that detached promise can
// leave the file's harness waiting at exit, which hangs the whole run instead
// of failing it. `--test-force-exit` lets each file's root test exit once its
// tests and hooks are done, regardless of that leftover. It only fires after
// the file is finished, so no result is lost.
const code = await spawnAndWait(
  process.execPath,
  ['--test', '--test-force-exit', `--test-concurrency=${limit}`, 'test/*.test.js'],
  { env: { ...process.env, TWEXTHUB_TEST_ISOLATED: limit > 1 ? '1' : '0' } },
);

await dropClones();
process.exit(code);
