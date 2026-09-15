/** The user row, and the checks that several routes need to share. */

import { HttpError, unauthorized } from "./http";
import { type Plan, planFor } from "./plans";

export interface UserRow {
  id: string;
  email_index: string;
  email_enc: string;
  auth_hash: string;
  server_salt: string;
  kdf_iterations: number;
  protected_key: string;
  recovery_wrap: string | null;
  recovery_hash: string | null;
  recovery_salt: string | null;
  recovery_created_at: number | null;
  email_verified: number;
  status: string;
  plan: string;
  plan_status: string | null;
  plan_period_end: number | null;
  stripe_customer_index: string | null;
  stripe_customer_enc: string | null;
  stripe_subscription_enc: string | null;
  totp_enabled: number;
  totp_secret_enc: string | null;
  totp_backup_enc: string | null;
  created_at: number;
  updated_at: number;
  last_login_at: number | null;
}

/** Unverified accounts work normally for this long, then go read-only. */
export const VERIFY_GRACE_MS = 7 * 24 * 60 * 60 * 1000;

export async function loadUser(env: Env, userId: string): Promise<UserRow> {
  const user = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`)
    .bind(userId)
    .first<UserRow>();
  if (!user) throw unauthorized("That account no longer exists.");
  if (user.status === "suspended") {
    throw new HttpError(403, "suspended", "This account has been suspended.");
  }
  return user;
}

export const planOf = (user: UserRow): Plan => planFor(user.plan, user.plan_status);

/**
 * Writing to a vault requires a confirmed address once the grace period is up.
 * Reading is always allowed. Locking someone out of passwords they already
 * own would be a worse outcome than an unverified address.
 */
export function assertCanWrite(env: Env, user: UserRow): void {
  if (user.email_verified === 1) return;
  if (Date.now() - user.created_at < VERIFY_GRACE_MS) return;
  // If this instance cannot send mail, nobody can confirm an address, and
  // locking a vault for failing to do the impossible would be indefensible.
  if (!env.EMAIL) return;
  throw new HttpError(
    403,
    "email_unverified",
    "Confirm your email address to add or change items. Your existing items are still readable.",
  );
}
