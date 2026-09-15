/**
 * Session handling.
 *
 * The cookie carries 256 bits of randomness. D1 stores only HMAC(pepper, token),
 * so a database read cannot mint a session, and the peppering means the hashes
 * cannot be precomputed either. Sessions expire twice over: an idle timeout that
 * slides forward with use, and an absolute ceiling that does not.
 */

import type { UserRow } from "./accounts";
import { randomToken, timingSafeEqual } from "./crypto";
import { planOf } from "./accounts";
import { pepper, seal } from "./serverkey";

export const COOKIE_NAME = "kp_session";

const IDLE_MS = 30 * 60 * 1000;
const ABSOLUTE_MS = 12 * 60 * 60 * 1000;

/**
 * `full` is an ordinary signed-in session. `recovery` is issued only by the
 * Recovery Key flow and may do exactly one thing. Finish that flow. It can
 * never read an item.
 */
export type SessionScope = "full" | "recovery";

export interface Session {
  id: string;
  userId: string;
  scope: SessionScope;
}

const tokenId = (env: Env, token: string) => pepper(env, `session:${token}`);

/**
 * Turns a client-supplied device id into a stored blind index.
 *
 * The id is not a secret and not a credential; it exists so the same browser
 * can be recognised across sign-ins. It is hashed anyway, because a plain list
 * of device ids per account is a correlation risk for no benefit.
 */
export async function deviceIndexOf(env: Env, deviceId: string | null): Promise<string | null> {
  if (!deviceId) return null;
  return pepper(env, `device:${deviceId}`);
}

export async function createSession(
  env: Env,
  userId: string,
  request: Request,
  scope: SessionScope = "full",
  deviceIndex: string | null = null,
): Promise<{ token: string; expiresAt: number }> {
  const token = randomToken();
  const id = await tokenId(env, token);
  const now = Date.now();

  // A recovery session is short-lived by design: it exists for one task.
  const idle = scope === "recovery" ? 30 * 60 * 1000 : IDLE_MS;
  const expiresAt = now + idle;

  const label = await seal(
    env,
    (request.headers.get("user-agent") ?? "unknown").slice(0, 300),
    `session.label:${id}`,
  );

  // A known device replaces its own session instead of adding one. Without
  // this, moving between a work machine and a home machine in the same day
  // burns a slot each time and trips a limit the person has not actually
  // exceeded.
  if (deviceIndex && scope === "full") {
    await env.DB.prepare(
      `DELETE FROM sessions WHERE user_id = ? AND device_index = ? AND scope = 'full'`,
    )
      .bind(userId, deviceIndex)
      .run();
  }

  await env.DB.prepare(
    `INSERT INTO sessions (id, user_id, scope, device_index, created_at, expires_at,
                           absolute_end, last_seen_at, label_enc)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      userId,
      scope,
      deviceIndex,
      now,
      expiresAt,
      now + (scope === "recovery" ? idle : ABSOLUTE_MS),
      now,
      label,
    )
    .run();

  return { token, expiresAt };
}

/**
 * The browser extension cannot use the cookie: it is SameSite=Strict, so a
 * request from a chrome-extension:// origin will never carry it. A bearer token
 * is the same 256 bits of randomness presented a different way, and because it
 * is not ambient it cannot be used for CSRF.
 */
function readBearer(request: Request): string | null {
  const header = request.headers.get("authorization");
  if (!header?.startsWith("Bearer ")) return null;
  const token = header.slice(7).trim();
  return token.length > 0 ? token : null;
}

/** Resolves the credential to a live session, sliding the idle window forward. */
export async function resolveSession(env: Env, request: Request): Promise<Session | null> {
  const token = readCookie(request, COOKIE_NAME) ?? readBearer(request);
  if (!token) return null;

  const id = await tokenId(env, token);
  const now = Date.now();

  const row = await env.DB.prepare(
    `SELECT id, user_id, scope, expires_at, absolute_end FROM sessions WHERE id = ?`,
  )
    .bind(id)
    .first<{
      id: string;
      user_id: string;
      scope: SessionScope;
      expires_at: number;
      absolute_end: number;
    }>();

  if (!row) return null;
  if (row.expires_at <= now || row.absolute_end <= now) {
    await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(id).run();
    return null;
  }

  // Extend, but never past the absolute ceiling.
  await env.DB.prepare(`UPDATE sessions SET expires_at = ?, last_seen_at = ? WHERE id = ?`)
    .bind(Math.min(now + IDLE_MS, row.absolute_end), now, id)
    .run();

  return { id: row.id, userId: row.user_id, scope: row.scope };
}

export async function destroySession(env: Env, request: Request): Promise<void> {
  const token = readCookie(request, COOKIE_NAME) ?? readBearer(request);
  if (!token) return;
  await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(await tokenId(env, token)).run();
}

export async function destroyOtherSessions(env: Env, session: Session): Promise<number> {
  const result = await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ? AND id != ?`)
    .bind(session.userId, session.id)
    .run();
  return result.meta.changes ?? 0;
}

export async function destroyAllSessions(env: Env, userId: string): Promise<void> {
  await env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId).run();
}

/**
 * Enforces the device limit by dropping the least recently used sessions, and
 * reports how many it dropped.
 *
 * Expired sessions are cleared first and excluded from the count. Without that,
 * a dead session from this morning still occupies a slot until the nightly
 * sweep, so somebody on a two device plan gets signed out of their phone by
 * their own laptop from twelve hours ago. The limit should count devices in
 * use, not ghosts.
 *
 * Signing the oldest out is friendlier than refusing the newest sign-in:
 * somebody locked out of the device in their hand cannot reach the setting that
 * would fix it.
 */
export async function trimSessionsToLimit(env: Env, user: UserRow): Promise<number> {
  const limit = planOf(user).devices;
  if (limit === null) return 0;

  const now = Date.now();
  await env.DB.prepare(
    `DELETE FROM sessions WHERE user_id = ? AND (expires_at <= ?2 OR absolute_end <= ?2)`,
  )
    .bind(user.id, now)
    .run();

  const result = await env.DB.prepare(
    `DELETE FROM sessions
      WHERE user_id = ?1 AND scope = 'full' AND id NOT IN (
        SELECT id FROM sessions
         WHERE user_id = ?1 AND scope = 'full' AND expires_at > ?3 AND absolute_end > ?3
         ORDER BY last_seen_at DESC LIMIT ?2
      )`,
  )
    .bind(user.id, limit, now)
    .run();

  return result.meta.changes ?? 0;
}

/** Housekeeping. Expired rows are useless and should not accumulate. */
export async function purgeExpired(env: Env): Promise<void> {
  const now = Date.now();
  await env.DB.batch([
    env.DB.prepare(`DELETE FROM sessions WHERE expires_at <= ? OR absolute_end <= ?`).bind(now, now),
    env.DB.prepare(`DELETE FROM tokens WHERE expires_at <= ? OR used_at IS NOT NULL`).bind(now),
  ]);
}

export function sessionCookie(token: string, maxAgeSeconds: number): string {
  // Secure + HttpOnly keeps it off the page entirely; SameSite=Strict means no
  // cross-site request can ever carry it, which is the CSRF defence.
  return [
    `${COOKIE_NAME}=${token}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${maxAgeSeconds}`,
  ].join("; ");
}

export const clearedCookie = (): string =>
  `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;

function readCookie(request: Request, name: string): string | null {
  const header = request.headers.get("cookie");
  if (!header) return null;
  for (const part of header.split(";")) {
    const eq = part.indexOf("=");
    if (eq === -1) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export { readBearer, timingSafeEqual };
