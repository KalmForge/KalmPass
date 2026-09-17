/**
 * Turns a nightly backup back into SQL.
 *
 *   npm run backup:restore -- 2026-09-17
 *
 * Downloads that day's backup from the kalmpass-backups bucket and writes
 * private/restore-<day>.sql, a set of INSERT OR REPLACE statements. It changes
 * nothing by itself. To restore into a fresh database:
 *
 *   npx wrangler d1 create kalmpass-restore
 *   npx wrangler d1 execute kalmpass-restore --remote --file=schema.sql
 *   npx wrangler d1 execute kalmpass-restore --remote --file=private/restore-<day>.sql
 *
 * then point wrangler.jsonc at the new database and deploy. The rows only mean
 * anything to a Worker whose SERVER_KEY has the fingerprint in the manifest.
 *
 * For recent mistakes, D1's own point-in-time recovery is quicker:
 *   npx wrangler d1 time-travel restore kalmpass --timestamp=<when>
 */

import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";

const BUCKET = "kalmpass-backups";
const TABLES = ["users", "items", "passkeys", "tokens", "audit"];

const day = process.argv[2];
if (!/^\d{4}-\d{2}-\d{2}$/.test(day ?? "")) {
  console.log("Usage: npm run backup:restore -- YYYY-MM-DD");
  process.exit(1);
}

const scratch = join(tmpdir(), `kalmpass-restore-${day}`);
mkdirSync(scratch, { recursive: true });

function fetchObject(name) {
  const file = join(scratch, name);
  execFileSync(
    "npx",
    ["wrangler", "r2", "object", "get", `${BUCKET}/backups/${day}/${name}`, "--remote", "--file", file],
    { stdio: "pipe", shell: process.platform === "win32" },
  );
  return readFileSync(file);
}

const manifest = JSON.parse(fetchObject("manifest.json").toString("utf8"));
console.log(`Backup of ${new Date(manifest.createdAt).toISOString()}`);
console.log(`Made under server key ${manifest.keyFingerprint}`);

const literal = (value) => {
  if (value === null || value === undefined) return "NULL";
  if (typeof value === "number") return String(value);
  return `'${String(value).replace(/'/g, "''")}'`;
};

const statements = ["PRAGMA foreign_keys = OFF;"];
for (const table of TABLES) {
  let bytes = fetchObject(`${table}.ndjson.gz`);
  // R2 may hand the file back already decompressed.
  if (bytes[0] === 0x1f && bytes[1] === 0x8b) bytes = gunzipSync(bytes);
  const rows = bytes.toString("utf8").split("\n").filter(Boolean).map((line) => JSON.parse(line));

  if (rows.length !== manifest.tables[table]) {
    throw new Error(`${table}: the manifest says ${manifest.tables[table]} rows, the file has ${rows.length}.`);
  }
  for (const row of rows) {
    const columns = Object.keys(row);
    statements.push(
      `INSERT OR REPLACE INTO ${table} (${columns.join(", ")}) VALUES (${columns.map((c) => literal(row[c])).join(", ")});`,
    );
  }
  console.log(`  ${table}: ${rows.length} rows`);
}
statements.push("PRAGMA foreign_keys = ON;");

mkdirSync("private", { recursive: true });
const out = `private/restore-${day}.sql`;
writeFileSync(out, statements.join("\n") + "\n");
rmSync(scratch, { recursive: true, force: true });
console.log(`\nWrote ${out}. See the top of this script for how to load it.`);
