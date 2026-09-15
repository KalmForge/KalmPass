/**
 * Vault items.
 *
 * Every payload here is opaque. The Worker receives base64 ciphertext that only
 * your browser can read, wraps it in the server envelope, and stores the result.
 * There is no endpoint that returns a plaintext field, because the Worker never
 * holds one.
 */

import { assertCanWrite, loadUser, planOf } from "../accounts";
import { randomId } from "../crypto";
import {
  HttpError,
  badRequest,
  conflict,
  json,
  notFound,
  readJson,
  requireInt,
  requireString,
} from "../http";
import { open, seal } from "../serverkey";
import type { Session } from "../sessions";

/** A hard ceiling above any plan, so nothing can run away with storage. */
const MAX_ITEMS = 20_000;
const MAX_BLOB_CHARS = 512 * 1024;
const TRASH_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;

interface ItemRow {
  id: string;
  data: string;
  revision: number;
  created_at: number;
  updated_at: number;
  deleted_at: number | null;
}

const context = (id: string) => `item.data:${id}`;

function requireData(body: Record<string, unknown>): string {
  const raw = requireString(body, "data", { max: MAX_BLOB_CHARS });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) throw badRequest('"data" must be base64.');
  // 12-byte IV plus a 16-byte GCM tag is 28 bytes, so anything shorter than its
  // base64 form cannot be a well-formed envelope.
  if (raw.length < 40) throw badRequest('"data" is too short to be valid ciphertext.');
  return raw;
}

async function shape(env: Env, row: ItemRow) {
  return {
    id: row.id,
    data: await open(env, row.data, context(row.id)),
    revision: row.revision,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    deletedAt: row.deleted_at,
  };
}

async function countLive(env: Env, userId: string): Promise<number> {
  const row = await env.DB.prepare(`SELECT COUNT(*) AS n FROM items WHERE user_id = ?`)
    .bind(userId)
    .first<{ n: number }>();
  return row?.n ?? 0;
}

/**
 * Checks the account may write, and has room for `adding` more items.
 *
 * `overflow` is set by import, and is the whole point of this function. Someone
 * arriving from another manager pastes in everything they own at once; refusing
 * the batch because it is three items over a plan limit means they never
 * migrate, never get invested, and never become a customer. So an import is
 * allowed to overshoot the plan, and the account simply stops accepting new
 * items afterwards until it is under the limit again or upgraded.
 *
 * Existing items stay readable and editable either way. Going over a plan
 * should be a nudge, not a hostage situation.
 */
async function assertRoomFor(
  env: Env,
  session: Session,
  adding: number,
  { overflow = false } = {},
): Promise<void> {
  const user = await loadUser(env, session.userId);
  assertCanWrite(env, user);

  const plan = planOf(user);
  const current = await countLive(env, session.userId);

  // The hard ceiling is not a plan limit, it is a guard against one account
  // trying to use the database as free storage. Nothing legitimate approaches it.
  if (current + adding > MAX_ITEMS) {
    throw new HttpError(
      403,
      "quota_exceeded",
      `A vault is limited to ${MAX_ITEMS.toLocaleString()} items.`,
      { limit: MAX_ITEMS, current },
    );
  }

  if (overflow || plan.items === null) return;

  if (current + adding > plan.items) {
    throw new HttpError(
      403,
      "quota_exceeded",
      `The ${plan.name} plan holds ${plan.items} items. Everything you already have stays readable and editable.`,
      { plan: plan.id, limit: plan.items, current },
    );
  }
}

/** Editing an existing item needs the write check, but not the quota check. */
async function assertMayEdit(env: Env, session: Session): Promise<void> {
  assertCanWrite(env, await loadUser(env, session.userId));
}

/** Trash is a grace period, not an archive. Anything old enough is really gone. */
async function purgeOldTrash(env: Env, userId: string): Promise<void> {
  await env.DB.prepare(`DELETE FROM items WHERE user_id = ? AND deleted_at IS NOT NULL AND deleted_at < ?`)
    .bind(userId, Date.now() - TRASH_RETENTION_MS)
    .run();
}

// ---------------------------------------------------------------------------

/**
 * GET /api/items, the whole vault, trash included.
 *
 * `?since=` returns only rows touched after that timestamp, which is how a
 * second device catches up without re-downloading everything.
 */
export async function list(env: Env, request: Request, session: Session): Promise<Response> {
  await purgeOldTrash(env, session.userId);

  const sinceParam = new URL(request.url).searchParams.get("since");
  const since = sinceParam ? Number(sinceParam) : 0;
  if (!Number.isFinite(since) || since < 0) throw badRequest('"since" must be a timestamp.');

  const { results } = await env.DB.prepare(
    `SELECT id, data, revision, created_at, updated_at, deleted_at
       FROM items WHERE user_id = ? AND updated_at > ? ORDER BY updated_at ASC`,
  )
    .bind(session.userId, since)
    .all<ItemRow>();

  return json({
    items: await Promise.all(results.map((row) => shape(env, row))),
    serverTime: Date.now(),
  });
}

/** POST /api/items */
export async function create(env: Env, request: Request, session: Session): Promise<Response> {
  await assertRoomFor(env, session, 1);

  const data = requireData(await readJson(request));
  const id = randomId();
  const now = Date.now();

  await env.DB.prepare(
    `INSERT INTO items (id, user_id, data, revision, created_at, updated_at)
     VALUES (?, ?, ?, 1, ?, ?)`,
  )
    .bind(id, session.userId, await seal(env, data, context(id)), now, now)
    .run();

  return json({ id, revision: 1, createdAt: now, updatedAt: now }, { status: 201 });
}

/**
 * PUT /api/items/:id
 *
 * The caller must send the revision it last saw. If another device has written
 * since, the update is refused and the current row comes back, so a stale tab
 * can never silently clobber a newer password.
 */
export async function update(
  env: Env,
  request: Request,
  session: Session,
  id: string,
): Promise<Response> {
  await assertMayEdit(env, session);

  const body = await readJson(request);
  const data = requireData(body);
  const revision = requireInt(body, "revision", { min: 1, max: Number.MAX_SAFE_INTEGER });

  const current = await env.DB.prepare(
    `SELECT id, data, revision, created_at, updated_at, deleted_at
       FROM items WHERE id = ? AND user_id = ?`,
  )
    .bind(id, session.userId)
    .first<ItemRow>();
  if (!current) throw notFound("That item no longer exists.");

  if (current.revision !== revision) {
    throw conflict("This item changed on another device.", { current: await shape(env, current) });
  }

  const now = Date.now();
  const next = current.revision + 1;
  await env.DB.prepare(`UPDATE items SET data = ?, revision = ?, updated_at = ? WHERE id = ? AND user_id = ?`)
    .bind(await seal(env, data, context(id)), next, now, id, session.userId)
    .run();

  return json({ id, revision: next, updatedAt: now });
}

/** DELETE /api/items/:id, to the trash, recoverable for 30 days. */
export async function remove(env: Env, session: Session, id: string): Promise<Response> {
  const now = Date.now();
  const result = await env.DB.prepare(
    `UPDATE items SET deleted_at = ?, updated_at = ?, revision = revision + 1
       WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
  )
    .bind(now, now, id, session.userId)
    .run();

  if ((result.meta.changes ?? 0) === 0) throw notFound("That item is not in your vault.");
  return json({ ok: true, deletedAt: now });
}

/** POST /api/items/:id/restore */
export async function restore(env: Env, session: Session, id: string): Promise<Response> {
  const now = Date.now();
  const result = await env.DB.prepare(
    `UPDATE items SET deleted_at = NULL, updated_at = ?, revision = revision + 1
       WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL`,
  )
    .bind(now, id, session.userId)
    .run();

  if ((result.meta.changes ?? 0) === 0) throw notFound("That item is not in the trash.");
  return json({ ok: true });
}

/** DELETE /api/items/:id/purge. Gone for good. */
export async function purge(env: Env, session: Session, id: string): Promise<Response> {
  const result = await env.DB.prepare(`DELETE FROM items WHERE id = ? AND user_id = ?`)
    .bind(id, session.userId)
    .run();
  if ((result.meta.changes ?? 0) === 0) throw notFound("That item is not in your vault.");
  return json({ ok: true });
}

/** DELETE /api/items/trash. Empty the trash in one go. */
export async function emptyTrash(env: Env, session: Session): Promise<Response> {
  const result = await env.DB.prepare(
    `DELETE FROM items WHERE user_id = ? AND deleted_at IS NOT NULL`,
  )
    .bind(session.userId)
    .run();
  return json({ ok: true, purged: result.meta.changes ?? 0 });
}

/**
 * POST /api/items/bulk. Used by import.
 *
 * Written as one D1 batch so a partial import cannot leave the vault holding
 * half a file.
 */
export async function bulkCreate(env: Env, request: Request, session: Session): Promise<Response> {
  const body = await readJson(request, 16 * 1024 * 1024);
  const entries = body["items"];
  if (!Array.isArray(entries)) throw badRequest('"items" must be an array.');
  if (entries.length === 0) return json({ ok: true, created: 0, ids: [] });
  if (entries.length > 2000) throw badRequest("Import at most 2000 items at a time.");

  // An import may overshoot the plan limit. See assertRoomFor.
  await assertRoomFor(env, session, entries.length, { overflow: true });

  const now = Date.now();
  const ids: string[] = [];
  const statements = await Promise.all(
    entries.map(async (entry) => {
      if (entry === null || typeof entry !== "object" || Array.isArray(entry)) {
        throw badRequest("Each item must be an object.");
      }
      const data = requireData(entry as Record<string, unknown>);
      const id = randomId();
      ids.push(id);
      return env.DB.prepare(
        `INSERT INTO items (id, user_id, data, revision, created_at, updated_at)
         VALUES (?, ?, ?, 1, ?, ?)`,
      ).bind(id, session.userId, await seal(env, data, context(id)), now, now);
    }),
  );

  await env.DB.batch(statements);
  return json({ ok: true, created: ids.length, ids }, { status: 201 });
}
