/**
 * Unlocking with a passkey.
 *
 * Note what this deliberately does not do: it never verifies a WebAuthn
 * signature. The passkey is not being used as a signing credential here, it is
 * being used for its PRF output, a deterministic secret the authenticator will
 * produce only for this origin and only after the user has proved themselves to
 * the device.
 *
 * That secret is treated exactly as the Recovery Key is. The browser splits it
 * into an encryption branch, which wraps the vault key, and an auth branch,
 * whose hash lands here. So the phishing resistance comes from the credential
 * being bound to kalmpass.net by the platform, and the secrecy comes from the
 * secret never leaving the device in a form we could use.
 *
 * The consequence, stated plainly because it is a real trade: without signature
 * verification the server cannot distinguish a genuine authenticator from
 * somebody who has obtained the PRF output by other means. That is the same
 * position we are in with the Recovery Key, and acceptable for the same reason.
 */

import { loadUser } from "../accounts";
import * as audit from "../audit";
import { fromB64, pbkdf2, randomBytes, randomId, timingSafeEqual, toB64 } from "../crypto";
import { HttpError, clientIp, conflict, json, notFound, readJson, requireString } from "../http";
import { open, pepper, seal } from "../serverkey";
import {
  type Session,
  createSession,
  deviceIndexOf,
  sessionCookie,
  trimSessionsToLimit,
} from "../sessions";
import { assertNotLocked, clearFailures, recordFailure, throttleKey } from "../throttle";
import { requireBlob, requireCredentialId, requireKey } from "../validate";

const SESSION_MAX_AGE = 12 * 60 * 60;
const MAX_PASSKEYS = 10;

interface PasskeyRow {
  id: string;
  user_id: string;
  credential_index: string;
  credential_enc: string;
  auth_hash: string;
  server_salt: string;
  wrapped_key: string;
  label_enc: string | null;
  created_at: number;
  last_used_at: number | null;
}

const hashAuthKey = async (env: Env, authKey: Uint8Array, salt: Uint8Array) =>
  pepper(env, await pbkdf2(authKey, salt));

function optionalDeviceId(body: Record<string, unknown>): string | null {
  const value = body["deviceId"];
  if (typeof value !== "string") return null;
  return /^[A-Za-z0-9_-]{8,64}$/.test(value) ? value : null;
}

// ---------------------------------------------------------------------------

/** POST /api/account/passkeys. Registers one, from an already unlocked vault. */
export async function register(env: Env, request: Request, session: Session): Promise<Response> {
  const user = await loadUser(env, session.userId);
  const body = await readJson(request);

  const existing = await env.DB.prepare(`SELECT COUNT(*) AS n FROM passkeys WHERE user_id = ?`)
    .bind(user.id)
    .first<{ n: number }>();
  if ((existing?.n ?? 0) >= MAX_PASSKEYS) {
    throw conflict(`An account can hold ${MAX_PASSKEYS} passkeys. Remove one first.`);
  }

  const credentialId = requireCredentialId(body);
  const index = await pepper(env, `credential:${credentialId}`);

  const clash = await env.DB.prepare(`SELECT id FROM passkeys WHERE credential_index = ?`)
    .bind(index)
    .first<{ id: string }>();
  if (clash) throw conflict("That passkey is already registered.");

  const id = randomId();
  const salt = randomBytes(16);
  const now = Date.now();
  const label = requireString(body, "label", { max: 80 });

  await env.DB.prepare(
    `INSERT INTO passkeys (id, user_id, credential_index, credential_enc, auth_hash,
                           server_salt, wrapped_key, label_enc, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      id,
      user.id,
      index,
      await seal(env, credentialId, `passkey.credential:${id}`),
      await hashAuthKey(env, requireKey(body, "authKey"), salt),
      toB64(salt),
      await seal(env, requireBlob(body, "wrappedKey"), `passkey.wrapped:${id}`),
      await seal(env, label, `passkey.label:${id}`),
      now,
    )
    .run();

  await audit.record(env, user.id, "passkey_added", label);
  return json({ ok: true, id, label, createdAt: now }, { status: 201 });
}

/** GET /api/account/passkeys */
export async function list(env: Env, session: Session): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT id, label_enc, created_at, last_used_at FROM passkeys
      WHERE user_id = ? ORDER BY created_at DESC`,
  )
    .bind(session.userId)
    .all<{ id: string; label_enc: string | null; created_at: number; last_used_at: number | null }>();

  return json({
    passkeys: await Promise.all(
      results.map(async (row) => ({
        id: row.id,
        label: row.label_enc ? await open(env, row.label_enc, `passkey.label:${row.id}`) : "Passkey",
        createdAt: row.created_at,
        lastUsedAt: row.last_used_at,
      })),
    ),
  });
}

/** DELETE /api/account/passkeys/:id */
export async function remove(env: Env, session: Session, id: string): Promise<Response> {
  const result = await env.DB.prepare(`DELETE FROM passkeys WHERE id = ? AND user_id = ?`)
    .bind(id, session.userId)
    .run();

  if ((result.meta.changes ?? 0) === 0) throw notFound("That passkey is not on your account.");
  await audit.record(env, session.userId, "passkey_removed");
  return json({ ok: true });
}

/**
 * POST /api/account/passkey-login
 *
 * Public, because the whole point is signing in without having typed anything.
 * The credential id identifies the row; the auth branch of the PRF secret
 * proves the authenticator produced it.
 */
export async function login(env: Env, request: Request, ctx: ExecutionContext): Promise<Response> {
  const body = await readJson(request);
  const credentialId = requireCredentialId(body);
  const authKey = requireKey(body, "authKey");

  const now = Date.now();
  const index = await pepper(env, `credential:${credentialId}`);
  const keys = [
    await throttleKey(env, "recover", index),
    await throttleKey(env, "ip", clientIp(request)),
  ];
  await assertNotLocked(env, keys, now);

  const passkey = await env.DB.prepare(`SELECT * FROM passkeys WHERE credential_index = ?`)
    .bind(index)
    .first<PasskeyRow>();

  // Constant work whether or not the credential is known, so timing does not
  // reveal which passkeys this instance has heard of.
  const salt = passkey ? fromB64(passkey.server_salt) : randomBytes(16);
  const candidate = await hashAuthKey(env, authKey, salt);
  const ok = passkey ? timingSafeEqual(fromB64(candidate), fromB64(passkey.auth_hash)) : false;

  if (!passkey || !ok) {
    await recordFailure(env, keys, now);
    throw new HttpError(401, "unauthorized", "That passkey is not registered here.");
  }

  const user = await loadUser(env, passkey.user_id);
  await clearFailures(env, keys);

  const { token } = await createSession(
    env,
    user.id,
    request,
    "full",
    await deviceIndexOf(env, optionalDeviceId(body)),
  );
  const evicted = await trimSessionsToLimit(env, user);

  await env.DB.prepare(`UPDATE passkeys SET last_used_at = ? WHERE id = ?`)
    .bind(now, passkey.id)
    .run();
  await env.DB.prepare(`UPDATE users SET last_login_at = ? WHERE id = ?`).bind(now, user.id).run();
  ctx.waitUntil(audit.record(env, user.id, "login", "Passkey"));

  const wantsToken = body["tokenAuth"] === true;

  return json(
    {
      ok: true,
      email: await open(env, user.email_enc, `user.email:${user.id}`),
      kdfIterations: user.kdf_iterations,
      // The wrapped vault key for this passkey, opened by the encryption branch
      // of the secret the browser already holds.
      wrappedKey: await open(env, passkey.wrapped_key, `passkey.wrapped:${passkey.id}`),
      totpEnabled: user.totp_enabled === 1,
      emailVerified: user.email_verified === 1,
      plan: user.plan,
      planStatus: user.plan_status,
      deviceLimit: null,
      devicesSignedOut: evicted,
      ...(wantsToken ? { token } : {}),
    },
    wantsToken ? {} : { headers: { "set-cookie": sessionCookie(token, SESSION_MAX_AGE) } },
  );
}
