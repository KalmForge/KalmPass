/**
 * The account's own security log.
 *
 * Detail is enveloped like everything else, so the log is readable by its owner
 * through the app but is not a plaintext record of anyone's movements sitting in
 * the database.
 */

import { randomId } from "./crypto";
import { open, seal } from "./serverkey";

export type AuditKind =
  | "signup"
  | "login"
  | "login_failed"
  | "logout"
  | "password_changed"
  | "recovery_used"
  | "recovery_key_replaced"
  | "account_reset"
  | "email_verified"
  | "totp_enabled"
  | "totp_disabled"
  | "sessions_revoked"
  | "plan_changed"
  | "vault_exported";

export async function record(
  env: Env,
  userId: string,
  kind: AuditKind,
  detail: string = "",
): Promise<void> {
  const id = randomId();
  await env.DB.prepare(`INSERT INTO audit (id, user_id, kind, at, detail_enc) VALUES (?, ?, ?, ?, ?)`)
    .bind(id, userId, kind, Date.now(), detail ? await seal(env, detail, `audit:${id}`) : null)
    .run();
}

export async function list(env: Env, userId: string, limit = 50) {
  const { results } = await env.DB.prepare(
    `SELECT id, kind, at, detail_enc FROM audit WHERE user_id = ? ORDER BY at DESC LIMIT ?`,
  )
    .bind(userId, Math.min(limit, 200))
    .all<{ id: string; kind: string; at: number; detail_enc: string | null }>();

  return Promise.all(
    results.map(async (row) => ({
      kind: row.kind,
      at: row.at,
      detail: row.detail_enc ? await open(env, row.detail_enc, `audit:${row.id}`) : "",
    })),
  );
}

/** Keeps the log to a useful window rather than letting it grow without bound. */
export async function prune(env: Env, keepDays = 180): Promise<void> {
  await env.DB.prepare(`DELETE FROM audit WHERE at < ?`)
    .bind(Date.now() - keepDays * 86_400_000)
    .run();
}
