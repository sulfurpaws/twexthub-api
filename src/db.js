import {
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  unlinkSync,
  existsSync,
  rmSync,
} from 'node:fs';
import { copyFile, rm } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import postgres from 'postgres';
import { BLOB_GC_LOCK_KEY, blobPathFor, hashFile, sha512Base64 } from './blobs.js';

const moduleDir = path.dirname(fileURLToPath(import.meta.url));
export const MIGRATIONS_DIR = path.join(moduleDir, '..', 'migrations');

export function createDb(config) {
  const sql = postgres(config.database.url, {
    max: config.database.maxConnections,
    connect_timeout: config.database.connectTimeoutSeconds,
    idle_timeout: config.database.idleTimeoutSeconds,
    onnotice: () => {},
  });
  return sql;
}

export async function runMigrations(sql, migrationsDir = MIGRATIONS_DIR) {
  const { spawn } = await import('node:child_process');
  const { loadConfig } = await import('./config.js');

  const config = loadConfig();
  const url = config.database.url;

  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(32001)`;
    await tx.unsafe(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        version TEXT PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    await tx.unsafe(`
      CREATE TABLE IF NOT EXISTS _prisma_migrations (
        id TEXT PRIMARY KEY,
        checksum TEXT NOT NULL,
        finished_at TIMESTAMPTZ,
        migration_name TEXT NOT NULL,
        logs TEXT,
        rolled_back_at TIMESTAMPTZ,
        started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        applied_steps_count INTEGER NOT NULL DEFAULT 0
      )
    `);

    const legacyApplied = await tx`SELECT version FROM schema_migrations`;
    const legacySet = new Set(legacyApplied.map((r) => r.version));
    const prismaApplied = await tx`SELECT migration_name FROM _prisma_migrations`;
    const prismaSet = new Set(prismaApplied.map((r) => r.migration_name));

    if (prismaSet.size === 0 && legacySet.size > 0) {
      const required = [
        '0001_init.sql',
        '0002_pruning.sql',
        '0003_search_trgm.sql',
        '0004_query_indexes.sql',
        '0005_notifications.sql',
        '0006_blob_digest.sql',
        '0007_deprecated.sql',
        '0008_dist_tags.sql',
        '0009_download_metrics.sql',
        '0010_extension_owners.sql',
        '0011_owner_notifications.sql',
        '0012_webhooks.sql',
        '0013_profiles.sql',
        '0014_private_quotas_audit.sql',
        '0015_build_on_publish.sql',
        '0016_hardening_indexes.sql',
        '0017_download_address_hash.sql',
        '0018_webhook_delivery_lease.sql',
        '0019_profile_images.sql',
        '0020_organizations.sql',
        '0021_global_webhooks.sql',
        '0022_organization_notifications.sql',
        '0023_extension_owner_invites.sql',
        '0024_extension_transfers.sql',
        '0025_drop_private_extensions.sql',
        '0026_version_is_unsandboxed.sql',
        '0027_oidc.sql',
        '0028_version_warnings.sql',
        '0029_version_download_metrics.sql',
      ];
      if (legacySet.size !== required.length || !required.every((f) => legacySet.has(f))) {
        throw new Error('pre-Prisma upgrade error');
      }
    }
    if (prismaSet.size === 0 && legacySet.size === 0) {
      // fresh deployment - leave adoption to fresh deployment
    }
    // If neither exists, adoption handled by fresh deployment
  });

  const env = { ...process.env, DATABASE_URL: url };
  await new Promise((resolve, reject) => {
    const proc = spawn('npx', ['prisma', 'migrate', 'deploy', '--config', 'prisma.config.mjs'], {
      cwd: path.join(moduleDir, '..'),
      env,
      stdio: 'inherit',
    });
    proc.on('error', reject);
    proc.on('close', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`prisma migrate deploy exited with code ${code}`));
    });
  });
}

export async function reconcileOnBoot(sql, config) {
  const dataDir = config.dataDir;
  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(32002)`;
    const staging = await tx`
      SELECT * FROM versions
      WHERE status = 'staging' AND created_at < now() - interval '1 hour'
    `;
    for (const row of staging) {
      const blobAbs = path.join(dataDir, row.blob_path);
      const sourceAbs = row.source_path ? path.join(dataDir, row.source_path) : null;
      const complete = existsSync(blobAbs) && (!sourceAbs || existsSync(sourceAbs));
      if (complete) {
        // The namespace account decides the status, same as the live publish
        // path: a delegated publisher's own history says nothing about whether
        // this namespace still goes through review.
        const [account] =
          await tx`SELECT has_published FROM users WHERE namespace = ${row.namespace}`;
        const status = account?.has_published ? 'published' : 'pending';
        await tx`
          UPDATE versions
          SET status = ${status}, published_at = ${status === 'published' ? new Date() : null}
          WHERE id = ${row.id}
        `;
        console.log(
          `reconciled staging version ${row.namespace}/${row.extension_id}@${row.version} -> ${status}`,
        );
      } else {
        // The charge committed with the staging row, so dropping the row has to
        // give the bytes back the delete path would refund.
        const charge = Number(row.blob_size ?? 0) + Number(row.source_size ?? 0);
        if (charge > 0) {
          await tx`
            UPDATE users SET blob_bytes = GREATEST(blob_bytes - ${charge}, 0)
            WHERE namespace = ${row.namespace}
          `;
        }
        await tx`DELETE FROM versions WHERE id = ${row.id}`;
        console.log(
          `removed staging version ${row.namespace}/${row.extension_id}@${row.version} (blob or source missing)`,
        );
      }
    }
  });

  const tmpDir = path.join(dataDir, 'tmp');
  mkdirSync(tmpDir, { recursive: true });
  const cutoff = Date.now() - 3600_000;
  for (const entry of readdirSync(tmpDir)) {
    const entryPath = path.join(tmpDir, entry);
    try {
      const st = statSync(entryPath);
      if (st.isFile() && st.mtimeMs < cutoff) unlinkSync(entryPath);
    } catch {
      // another process may have already removed it
    }
  }

  const quarantineDir = path.join(dataDir, 'quarantine');
  mkdirSync(quarantineDir, { recursive: true });
  for (const entry of readdirSync(quarantineDir, { withFileTypes: true })) {
    const entryPath = path.join(quarantineDir, entry.name);
    try {
      const st = statSync(entryPath);
      if (st.isDirectory() && st.mtimeMs < cutoff) {
        rmSync(entryPath, { recursive: true, force: true });
      }
    } catch {
      // another process may have already removed it
    }
  }

  const maxWindow = Math.max(
    config.rateLimits.loginWindowMinutes,
    config.rateLimits.signupWindowMinutes,
  );
  const rateCutoff = new Date(Date.now() - maxWindow * 60_000);
  await sql`DELETE FROM rate_limit_entries WHERE window_start < ${rateCutoff}`;

  await sql`DELETE FROM sessions WHERE expires_at < now()`;
  await sql`DELETE FROM oidc_flows WHERE expires_at < now()`;

  // Pre-digest rows (published before the blob_digest migration) point at
  // legacy namespace/blob paths. Re-key them to content-addressed digests so
  // the whole table can be served from /blobs/:digest and evicted by GC.
  //
  // Two instances starting at once would select the same rows and then race on
  // the same files, so the pass runs under the blob GC lock and picks its rows
  // only once it holds it: by then a peer has finished and written their
  // digests, and those rows no longer match.
  const legacyPaths = [];
  await sql.begin(async (tx) => {
    await tx`SELECT pg_advisory_xact_lock(hashtextextended(${BLOB_GC_LOCK_KEY}, 0))`;
    const legacy = await tx`
      SELECT * FROM versions
      WHERE blob_digest IS NULL AND status IN ('published', 'yanked', 'deprecated')
    `;
    for (const row of legacy) {
      const legacyPath = path.join(dataDir, row.blob_path);
      let digest;
      try {
        digest = await hashFile(legacyPath);
      } catch {
        console.warn(
          `indexing skipped for ${row.namespace}/${row.extension_id}@${row.version}: missing blob`,
        );
        continue;
      }
      const codeBuffer = readFileSync(legacyPath);
      const digestAbs = blobPathFor(dataDir, digest);
      // The shard for a digest that has never been stored is not there yet, and
      // nothing else in the data directory creates it.
      mkdirSync(path.dirname(digestAbs), { recursive: true });
      await copyFile(legacyPath, digestAbs);
      await tx`
        UPDATE versions
        SET blob_digest = ${digest},
            blob_size = ${codeBuffer.length},
            blob_sha512 = ${sha512Base64(codeBuffer)},
            blob_path = ${path.join('blobs', digest.slice(0, 2), digest.slice(2))}
      WHERE id = ${row.id}
      `;
      if (legacyPath !== digestAbs) {
        legacyPaths.push(legacyPath);
      }
    }
  });
  for (const legacyPath of legacyPaths) {
    await rm(legacyPath, { force: true });
  }
}

export function ensureDataDirs(dataDir) {
  mkdirSync(path.join(dataDir, 'blobs'), { recursive: true });
  mkdirSync(path.join(dataDir, 'tmp'), { recursive: true });
  mkdirSync(path.join(dataDir, 'quarantine'), { recursive: true });
}
