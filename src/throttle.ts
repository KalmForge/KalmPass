/**
 * Login throttling.
 *
 * Counters are keyed by blind index, never by the address or IP itself, so the
 * throttle table cannot be read as a log of who tried to sign in from where.
 * Email and IP are tracked separately: someone hammering the endpoint from one
 * address cannot lock your account out, and a botnet spreading attempts across
 * many addresses still trips the per-account counter.
 */

import { HttpError } from "./http";
import { pepper } from "./serverkey";

const WINDOW_MS = 15 * 60 * 1000;
const FREE_ATTEMPTS = 5;
const BASE_LOCK_MS = 30 * 1000;
const MAX_LOCK_MS = 30 * 60 * 1000;

/**
 * `recover` is counted separately from `email` so that guessing at the Recovery
 * Key cannot lock someone out of an ordinary sign-in, and vice versa.
 */
export type ThrottleKind = "email" | "ip" | "recover";

export async function throttleKey(env: Env, kind: ThrottleKind, value: string): Promise<string> {
  return pepper(env, `throttle:${kind}:${value}`);
}

/** Throws 429 if the key is currently locked out. */
export async function assertNotLocked(env: Env, keys: string[], now: number): Promise<void> {
  if (keys.length === 0) return;
  const placeholders = keys.map(() => "?").join(", ");
  const row = await env.DB.prepare(
    `SELECT MAX(locked_until) AS locked_until FROM throttle
      WHERE key IN (${placeholders}) AND locked_until > ?`,
  )
    .bind(...keys, now)
    .first<{ locked_until: number | null }>();

  const until = row?.locked_until ?? null;
  if (until && until > now) {
    const seconds = Math.ceil((until - now) / 1000);
    throw new HttpError(
      429,
      "locked_out",
      `Too many failed attempts. Try again in ${seconds} second${seconds === 1 ? "" : "s"}.`,
      { retryAfter: seconds },
    );
  }
}

export async function recordFailure(env: Env, keys: string[], now: number): Promise<void> {
  await env.DB.batch(
    keys.map((key) =>
      env.DB.prepare(
        `INSERT INTO throttle (key, fails, first_fail_at, locked_until)
         VALUES (?1, 1, ?2, NULL)
         ON CONFLICT(key) DO UPDATE SET
           -- A quiet fifteen minutes resets the counter, so an honest typo
           -- yesterday does not compound with one today.
           fails = CASE WHEN throttle.first_fail_at < ?3 THEN 1 ELSE throttle.fails + 1 END,
           first_fail_at = CASE WHEN throttle.first_fail_at < ?3 THEN ?2 ELSE throttle.first_fail_at END,
           locked_until = CASE
             WHEN (CASE WHEN throttle.first_fail_at < ?3 THEN 1 ELSE throttle.fails + 1 END) > ?4
             THEN ?2 + MIN(?5 * (1 << MIN(
               (CASE WHEN throttle.first_fail_at < ?3 THEN 1 ELSE throttle.fails + 1 END) - ?4 - 1, 16)), ?6)
             ELSE NULL
           END`,
      ).bind(key, now, now - WINDOW_MS, FREE_ATTEMPTS, BASE_LOCK_MS, MAX_LOCK_MS),
    ),
  );
}

export async function clearFailures(env: Env, keys: string[]): Promise<void> {
  if (keys.length === 0) return;
  const placeholders = keys.map(() => "?").join(", ");
  await env.DB.prepare(`DELETE FROM throttle WHERE key IN (${placeholders})`)
    .bind(...keys)
    .run();
}
