/**
 * Nightly backups of the database to R2.
 *
 * Every table that holds something worth keeping is written out as gzipped
 * JSON lines under backups/YYYY-MM-DD/, with a manifest listing the row counts
 * and the fingerprint of the SERVER_KEY the rows were sealed under. Sessions
 * and rate-limit counters are left out: they are short-lived and rebuilding
 * them is harmless.
 *
 * Nothing here weakens the encryption. Vault items are already ciphertext
 * under keys only their owners hold, and everything else sensitive is sealed
 * with the server envelope. A backup is only restorable together with the
 * matching SERVER_KEY, which is why the manifest records its fingerprint.
 *
 * The bucket deletes backups after 35 days (a lifecycle rule on the bucket),
 * on top of D1's own 30-day point-in-time recovery.
 */

import { keyFingerprint } from "./serverkey";

const TABLES = ["users", "items", "passkeys", "tokens", "audit"] as const;
const PAGE = 500;
export const BACKUP_PREFIX = "backups/";

export interface BackupManifest {
  createdAt: number;
  keyFingerprint: string;
  tables: Record<string, number>;
  bytes: number;
}

async function gzip(text: string): Promise<ArrayBuffer> {
  const stream = new Blob([text]).stream().pipeThrough(new CompressionStream("gzip"));
  return new Response(stream).arrayBuffer();
}

export async function runBackup(env: Env, now = Date.now()): Promise<BackupManifest | null> {
  if (!env.BACKUPS) return null;

  const day = new Date(now).toISOString().slice(0, 10);
  const folder = `${BACKUP_PREFIX}${day}/`;
  const manifest: BackupManifest = {
    createdAt: now,
    keyFingerprint: await keyFingerprint(env),
    tables: {},
    bytes: 0,
  };

  for (const table of TABLES) {
    const lines: string[] = [];
    // rowid order is stable and cheap to page through.
    for (let offset = 0; ; offset += PAGE) {
      const { results } = await env.DB.prepare(
        `SELECT * FROM ${table} ORDER BY rowid LIMIT ? OFFSET ?`,
      )
        .bind(PAGE, offset)
        .all<Record<string, unknown>>();
      for (const row of results) lines.push(JSON.stringify(row));
      if (results.length < PAGE) break;
    }

    const body = await gzip(lines.length ? lines.join("\n") + "\n" : "");
    await env.BACKUPS.put(`${folder}${table}.ndjson.gz`, body, {
      httpMetadata: { contentType: "application/x-ndjson", contentEncoding: "gzip" },
    });
    manifest.tables[table] = lines.length;
    manifest.bytes += body.byteLength;
  }

  // Written last, so a manifest only exists for a backup that finished.
  await env.BACKUPS.put(`${folder}manifest.json`, JSON.stringify(manifest, null, 2), {
    httpMetadata: { contentType: "application/json" },
  });
  return manifest;
}

/** The most recent finished backup, for the admin dashboard. */
export async function latestBackup(env: Env): Promise<BackupManifest | null> {
  if (!env.BACKUPS) return null;
  const listing = await env.BACKUPS.list({ prefix: BACKUP_PREFIX, delimiter: "/" });
  const days = [...listing.delimitedPrefixes].sort().reverse();
  for (const folder of days) {
    const object = await env.BACKUPS.get(`${folder}manifest.json`);
    if (object) return (await object.json()) as BackupManifest;
  }
  return null;
}
