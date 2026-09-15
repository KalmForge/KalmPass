/**
 * Account lifecycle: signup, email confirmation, login, the second factor,
 * master password changes, Recovery Key use, and the last-resort account reset.
 *
 * The thing to understand before changing anything here: no route in this file
 * can produce vault plaintext, and none is *meant* to. Recovery works by handing
 * back a differently-wrapped copy of a key the client already needs a secret to
 * open. A bug here can lock someone out, but it cannot leak a vault.
 */

import { type UserRow, loadUser } from "../accounts";
import * as audit from "../audit";
import {
  DEFAULT_KDF_ITERATIONS,
  KEY_BYTES,
  MAX_KDF_ITERATIONS,
  MIN_KDF_ITERATIONS,
  RECOVERY_CODE_COUNT,
} from "../constants";
import { fromB64, pbkdf2, randomBytes, randomId, randomToken, timingSafeEqual, toB64, toB64Url } from "../crypto";
import * as mail from "../email";
import {
  HttpError,
  badRequest,
  clientIp,
  conflict,
  json,
  readJson,
  requireInt,
  requireString,
  unauthorized,
} from "../http";
import { PLANS } from "../plans";
import { emailIndex, normalizeEmail, open, pepper, seal } from "../serverkey";
import {
  type Session,
  clearedCookie,
  createSession,
  destroyAllSessions,
  destroyOtherSessions,
  destroySession,
  sessionCookie,
  trimSessionsToLimit,
} from "../sessions";
import { assertNotLocked, clearFailures, recordFailure, throttleKey } from "../throttle";
import { generateTotpSecret, verifyTotp } from "../totp";

const SESSION_MAX_AGE = 12 * 60 * 60;
const VERIFY_TOKEN_MS = 24 * 60 * 60 * 1000;
const RESET_TOKEN_MS = 60 * 60 * 1000;

// --- validation -------------------------------------------------------------

/** A 32-byte base64 value, validated before it is allowed anywhere near the DB. */
function requireKey(body: Record<string, unknown>, field: string): Uint8Array {
  const raw = requireString(body, field, { max: 128 });
  let bytes: Uint8Array;
  try {
    bytes = fromB64(raw);
  } catch {
    throw badRequest(`"${field}" must be base64.`);
  }
  if (bytes.length !== KEY_BYTES) throw badRequest(`"${field}" must decode to ${KEY_BYTES} bytes.`);
  return bytes;
}

/** base64(iv || ciphertext) produced by the browser. Opaque here, but bounded. */
function requireBlob(body: Record<string, unknown>, field: string, max = 4096): string {
  const raw = requireString(body, field, { max });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) throw badRequest(`"${field}" must be base64.`);
  if (raw.length < 24) throw badRequest(`"${field}" is too short to be valid ciphertext.`);
  return raw;
}

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function requireEmail(body: Record<string, unknown>): string {
  const email = requireString(body, "email", { max: 320 });
  if (!EMAIL_PATTERN.test(email)) throw badRequest("Enter a valid email address.");
  return normalizeEmail(email);
}

function requireIterations(body: Record<string, unknown>): number {
  return requireInt(body, "kdfIterations", {
    min: MIN_KDF_ITERATIONS,
    max: MAX_KDF_ITERATIONS,
  });
}

/** The client's KDF output, hashed again with a server pepper before storage. */
const hashAuthKey = async (env: Env, authKey: Uint8Array, salt: Uint8Array) =>
  pepper(env, await pbkdf2(authKey, salt));

async function assertMasterPassword(
  env: Env,
  user: UserRow,
  body: Record<string, unknown>,
): Promise<void> {
  const hash = await hashAuthKey(env, requireKey(body, "currentAuthKey"), fromB64(user.server_salt));
  if (!timingSafeEqual(fromB64(hash), fromB64(user.auth_hash))) {
    throw unauthorized("Master password is incorrect.");
  }
}

// --- one-shot email tokens --------------------------------------------------

async function issueToken(env: Env, userId: string, kind: string, ttlMs: number): Promise<string> {
  const token = randomToken();
  // Only the HMAC is stored, so the tokens table cannot be read back into
  // working links even with full database access.
  await env.DB.prepare(
    `INSERT INTO tokens (id, user_id, kind, created_at, expires_at) VALUES (?, ?, ?, ?, ?)`,
  )
    .bind(await pepper(env, `token:${kind}:${token}`), userId, kind, Date.now(), Date.now() + ttlMs)
    .run();
  return token;
}

async function consumeToken(env: Env, token: string, kind: string): Promise<string> {
  const id = await pepper(env, `token:${kind}:${token}`);
  const row = await env.DB.prepare(
    `SELECT user_id, expires_at, used_at FROM tokens WHERE id = ? AND kind = ?`,
  )
    .bind(id, kind)
    .first<{ user_id: string; expires_at: number; used_at: number | null }>();

  if (!row || row.used_at || row.expires_at <= Date.now()) {
    throw new HttpError(400, "bad_token", "That link has expired or has already been used.");
  }
  await env.DB.prepare(`UPDATE tokens SET used_at = ? WHERE id = ?`).bind(Date.now(), id).run();
  return row.user_id;
}

// ---------------------------------------------------------------------------

/** GET /api/account/status */
export async function status(env: Env): Promise<Response> {
  return json({
    signupAllowed: env.ALLOW_SIGNUP !== "false",
    setupCodeRequired: Boolean(env.SIGNUP_TOKEN),
    billingEnabled: Boolean(env.STRIPE_SECRET_KEY && env.STRIPE_PRICE_ID),
    defaultKdfIterations: DEFAULT_KDF_ITERATIONS,
    plans: PLANS,
  });
}

/**
 * POST /api/account/prelogin
 *
 * Answers identically for an unknown address, so this cannot be used to test
 * whether someone has an account here.
 */
export async function prelogin(env: Env, request: Request): Promise<Response> {
  const body = await readJson(request);
  const user = await env.DB.prepare(`SELECT kdf_iterations FROM users WHERE email_index = ?`)
    .bind(await emailIndex(env, requireString(body, "email", { max: 320 })))
    .first<{ kdf_iterations: number }>();
  return json({ kdfIterations: user?.kdf_iterations ?? DEFAULT_KDF_ITERATIONS });
}

/** POST /api/account/signup */
export async function signup(env: Env, request: Request, ctx: ExecutionContext): Promise<Response> {
  if (env.ALLOW_SIGNUP === "false") {
    throw new HttpError(403, "signup_closed", "KalmPass is not accepting new accounts right now.");
  }

  const body = await readJson(request);

  // An invite code, if the instance is running a closed beta.
  if (env.SIGNUP_TOKEN) {
    const submitted = requireString(body, "setupCode", { max: 256 });
    const encoder = new TextEncoder();
    const ok = timingSafeEqual(
      await pbkdf2(encoder.encode(submitted), encoder.encode("setup"), 1),
      await pbkdf2(encoder.encode(env.SIGNUP_TOKEN), encoder.encode("setup"), 1),
    );
    if (!ok) throw new HttpError(403, "bad_setup_code", "That invite code is not right.");
  }

  const email = requireEmail(body);
  const authKey = requireKey(body, "authKey");
  const kdfIterations = requireIterations(body);
  const protectedKey = requireBlob(body, "protectedKey");
  const recoveryWrap = requireBlob(body, "recoveryWrap");
  const recoveryAuthKey = requireKey(body, "recoveryAuthKey");

  const index = await emailIndex(env, email);
  const existing = await env.DB.prepare(`SELECT id FROM users WHERE email_index = ?`)
    .bind(index)
    .first<{ id: string }>();
  if (existing) throw conflict("There is already an account for that address. Sign in instead.");

  const now = Date.now();
  const id = randomId();
  const serverSalt = randomBytes(16);
  const recoverySalt = randomBytes(16);

  await env.DB.prepare(
    `INSERT INTO users (id, email_index, email_enc, auth_hash, server_salt, kdf_iterations,
                        protected_key, recovery_wrap, recovery_hash, recovery_salt,
                        recovery_created_at, email_verified, status, plan,
                        totp_enabled, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 'active', 'free', 0, ?, ?)`,
  )
    .bind(
      id,
      index,
      await seal(env, email, `user.email:${id}`),
      await hashAuthKey(env, authKey, serverSalt),
      toB64(serverSalt),
      kdfIterations,
      await seal(env, protectedKey, `user.protected_key:${id}`),
      await seal(env, recoveryWrap, `user.recovery_wrap:${id}`),
      await hashAuthKey(env, recoveryAuthKey, recoverySalt),
      toB64(recoverySalt),
      now,
      now,
      now,
    )
    .run();

  await audit.record(env, id, "signup");

  // The confirmation mail must not hold the signup open; a slow SMTP hop is not
  // the customer's problem.
  const token = await issueToken(env, id, "verify_email", VERIFY_TOKEN_MS);
  ctx.waitUntil(mail.sendVerification(env, email, `${env.APP_URL}/app/?verify=${token}`));

  const { token: sessionToken } = await createSession(env, id, request, "full");
  return json(
    { ok: true, email, kdfIterations, totpEnabled: false, emailVerified: false, plan: "free" },
    { status: 201, headers: { "set-cookie": sessionCookie(sessionToken, SESSION_MAX_AGE) } },
  );
}

/** POST /api/account/login */
export async function login(env: Env, request: Request, ctx: ExecutionContext): Promise<Response> {
  const body = await readJson(request);
  const email = requireString(body, "email", { max: 320 });
  const authKey = requireKey(body, "authKey");
  const submittedTotp = typeof body["totp"] === "string" ? body["totp"] : null;
  const backupCode = typeof body["backupCode"] === "string" ? body["backupCode"] : null;

  const now = Date.now();
  const index = await emailIndex(env, email);
  const keys = [
    await throttleKey(env, "email", index),
    await throttleKey(env, "ip", clientIp(request)),
  ];
  await assertNotLocked(env, keys, now);

  const user = await env.DB.prepare(`SELECT * FROM users WHERE email_index = ?`)
    .bind(index)
    .first<UserRow>();

  // Always spend the same work, so response time does not disclose whether the
  // address is one we know.
  const salt = user ? fromB64(user.server_salt) : randomBytes(16);
  const candidate = await hashAuthKey(env, authKey, salt);
  const passwordOk = user ? timingSafeEqual(fromB64(candidate), fromB64(user.auth_hash)) : false;

  if (!user || !passwordOk) {
    await recordFailure(env, keys, now);
    if (user) await audit.record(env, user.id, "login_failed");
    throw unauthorized("Incorrect email or master password.");
  }
  if (user.status === "suspended") {
    throw new HttpError(403, "suspended", "This account has been suspended.");
  }

  if (user.totp_enabled === 1) {
    let passed = false;
    if (backupCode) passed = await consumeBackupCode(env, user, backupCode);
    else if (submittedTotp && user.totp_secret_enc) {
      passed = await verifyTotp(
        await open(env, user.totp_secret_enc, `user.totp:${user.id}`),
        submittedTotp,
      );
    }

    if (!passed) {
      await recordFailure(env, keys, now);
      const attempted = Boolean(submittedTotp || backupCode);
      // Only reachable once the master password is already correct, so the
      // existence of a second factor is not a signal an outsider can collect.
      throw new HttpError(
        401,
        attempted ? "totp_invalid" : "totp_required",
        attempted ? "That code was not accepted." : "Enter the code from your authenticator app.",
      );
    }
  }

  await clearFailures(env, keys);
  const { token } = await createSession(env, user.id, request, "full");

  // Free plans are capped on simultaneous devices; the oldest gives way rather
  // than the newest being refused, which is what people actually expect.
  await trimSessionsToLimit(env, user);

  await env.DB.prepare(`UPDATE users SET last_login_at = ? WHERE id = ?`).bind(now, user.id).run();
  await audit.record(env, user.id, "login", describeAgent(request));

  const address = await open(env, user.email_enc, `user.email:${user.id}`);
  if (user.last_login_at && now - user.last_login_at > 14 * 86_400_000) {
    ctx.waitUntil(
      mail.sendNewDeviceAlert(env, address, describeAgent(request), new Date(now).toUTCString()),
    );
  }

  return json(
    {
      ok: true,
      email: address,
      kdfIterations: user.kdf_iterations,
      protectedKey: await open(env, user.protected_key, `user.protected_key:${user.id}`),
      totpEnabled: user.totp_enabled === 1,
      emailVerified: user.email_verified === 1,
      plan: user.plan,
      planStatus: user.plan_status,
    },
    { headers: { "set-cookie": sessionCookie(token, SESSION_MAX_AGE) } },
  );
}

/** POST /api/account/logout */
export async function logout(env: Env, request: Request): Promise<Response> {
  await destroySession(env, request);
  return json({ ok: true }, { headers: { "set-cookie": clearedCookie() } });
}

/** GET /api/account */
export async function me(env: Env, session: Session): Promise<Response> {
  const user = await loadUser(env, session.userId);
  const count = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM items WHERE user_id = ? AND deleted_at IS NULL`,
  )
    .bind(user.id)
    .first<{ n: number }>();

  return json({
    email: await open(env, user.email_enc, `user.email:${user.id}`),
    kdfIterations: user.kdf_iterations,
    protectedKey: await open(env, user.protected_key, `user.protected_key:${user.id}`),
    totpEnabled: user.totp_enabled === 1,
    emailVerified: user.email_verified === 1,
    hasRecoveryKey: Boolean(user.recovery_wrap),
    recoveryCreatedAt: user.recovery_created_at,
    plan: user.plan,
    planStatus: user.plan_status,
    planPeriodEnd: user.plan_period_end,
    itemCount: count?.n ?? 0,
    createdAt: user.created_at,
  });
}

// --- email confirmation -----------------------------------------------------

/** POST /api/account/verify — public, because the link may be opened anywhere. */
export async function verifyEmail(env: Env, request: Request): Promise<Response> {
  const token = requireString(await readJson(request), "token", { max: 128 });
  const userId = await consumeToken(env, token, "verify_email");

  await env.DB.prepare(`UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?`)
    .bind(Date.now(), userId)
    .run();
  await audit.record(env, userId, "email_verified");
  return json({ ok: true });
}

/** POST /api/account/resend-verification */
export async function resendVerification(
  env: Env,
  session: Session,
  ctx: ExecutionContext,
): Promise<Response> {
  const user = await loadUser(env, session.userId);
  if (user.email_verified === 1) return json({ ok: true, alreadyVerified: true });

  const token = await issueToken(env, user.id, "verify_email", VERIFY_TOKEN_MS);
  const address = await open(env, user.email_enc, `user.email:${user.id}`);
  ctx.waitUntil(mail.sendVerification(env, address, `${env.APP_URL}/app/?verify=${token}`));
  return json({ ok: true });
}

// --- master password --------------------------------------------------------

/**
 * POST /api/account/rekey — change the master password.
 *
 * The vault key does not change, so items are untouched: the browser re-wraps
 * that one key under the new password. Other sessions are dropped, because they
 * hold a key that no longer unwraps anything.
 */
export async function rekey(
  env: Env,
  request: Request,
  session: Session,
  ctx: ExecutionContext,
): Promise<Response> {
  const user = await loadUser(env, session.userId);
  const body = await readJson(request);
  await assertMasterPassword(env, user, body);

  const salt = randomBytes(16);
  await env.DB.prepare(
    `UPDATE users SET auth_hash = ?, server_salt = ?, kdf_iterations = ?,
                      protected_key = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(
      await hashAuthKey(env, requireKey(body, "authKey"), salt),
      toB64(salt),
      requireIterations(body),
      await seal(env, requireBlob(body, "protectedKey"), `user.protected_key:${user.id}`),
      Date.now(),
      user.id,
    )
    .run();

  await destroyOtherSessions(env, session);
  await audit.record(env, user.id, "password_changed");

  const address = await open(env, user.email_enc, `user.email:${user.id}`);
  ctx.waitUntil(mail.sendPasswordChanged(env, address, new Date().toUTCString()));
  return json({ ok: true });
}

// --- the Recovery Key -------------------------------------------------------

/**
 * POST /api/account/recover — step one of forgotten-password.
 *
 * Proves possession of the Recovery Key and hands back the copy of the vault key
 * that the Recovery Key wraps. That blob is useless without the key itself, which
 * we have never seen: all we hold is a hash of one HKDF branch of it.
 */
export async function recover(env: Env, request: Request): Promise<Response> {
  const body = await readJson(request);
  const email = requireString(body, "email", { max: 320 });
  const recoveryAuthKey = requireKey(body, "recoveryAuthKey");

  const now = Date.now();
  const index = await emailIndex(env, email);
  const keys = [
    await throttleKey(env, "recover", index),
    await throttleKey(env, "ip", clientIp(request)),
  ];
  await assertNotLocked(env, keys, now);

  const user = await env.DB.prepare(`SELECT * FROM users WHERE email_index = ?`)
    .bind(index)
    .first<UserRow>();

  const salt = user?.recovery_salt ? fromB64(user.recovery_salt) : randomBytes(16);
  const candidate = await hashAuthKey(env, recoveryAuthKey, salt);
  const ok =
    user?.recovery_hash != null &&
    timingSafeEqual(fromB64(candidate), fromB64(user.recovery_hash));

  if (!user || !ok || !user.recovery_wrap) {
    await recordFailure(env, keys, now);
    throw unauthorized("That email and Recovery Key do not match an account.");
  }

  await clearFailures(env, keys);

  // A recovery-scoped session can do exactly one thing: finish the recovery. It
  // cannot read items, change billing, or touch the second factor.
  const { token } = await createSession(env, user.id, request, "recovery");
  return json(
    {
      ok: true,
      email: await open(env, user.email_enc, `user.email:${user.id}`),
      recoveryWrap: await open(env, user.recovery_wrap, `user.recovery_wrap:${user.id}`),
    },
    { headers: { "set-cookie": sessionCookie(token, 30 * 60) } },
  );
}

/**
 * POST /api/account/recover/complete — step two.
 *
 * Sets a new master password and issues a fresh Recovery Key, because the old
 * one has now been typed into a browser and should be considered spent.
 */
export async function recoverComplete(
  env: Env,
  request: Request,
  session: Session,
  ctx: ExecutionContext,
): Promise<Response> {
  if (session.scope !== "recovery") {
    throw unauthorized("Start the recovery process again.");
  }

  const user = await loadUser(env, session.userId);
  const body = await readJson(request);

  const salt = randomBytes(16);
  const recoverySalt = randomBytes(16);
  const now = Date.now();

  await env.DB.prepare(
    `UPDATE users SET auth_hash = ?, server_salt = ?, kdf_iterations = ?, protected_key = ?,
                      recovery_wrap = ?, recovery_hash = ?, recovery_salt = ?,
                      recovery_created_at = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(
      await hashAuthKey(env, requireKey(body, "authKey"), salt),
      toB64(salt),
      requireIterations(body),
      await seal(env, requireBlob(body, "protectedKey"), `user.protected_key:${user.id}`),
      await seal(env, requireBlob(body, "recoveryWrap"), `user.recovery_wrap:${user.id}`),
      await hashAuthKey(env, requireKey(body, "recoveryAuthKey"), recoverySalt),
      toB64(recoverySalt),
      now,
      now,
      user.id,
    )
    .run();

  // Everything else goes, including this recovery session.
  await destroyAllSessions(env, user.id);
  await audit.record(env, user.id, "recovery_used");

  const address = await open(env, user.email_enc, `user.email:${user.id}`);
  ctx.waitUntil(mail.sendRecoveryUsed(env, address, new Date(now).toUTCString()));

  return json({ ok: true }, { headers: { "set-cookie": clearedCookie() } });
}

/** POST /api/account/recovery-key/rotate — issue a new Recovery Key on demand. */
export async function rotateRecoveryKey(
  env: Env,
  request: Request,
  session: Session,
): Promise<Response> {
  const user = await loadUser(env, session.userId);
  const body = await readJson(request);
  await assertMasterPassword(env, user, body);

  const recoverySalt = randomBytes(16);
  const now = Date.now();
  await env.DB.prepare(
    `UPDATE users SET recovery_wrap = ?, recovery_hash = ?, recovery_salt = ?,
                      recovery_created_at = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(
      await seal(env, requireBlob(body, "recoveryWrap"), `user.recovery_wrap:${user.id}`),
      await hashAuthKey(env, requireKey(body, "recoveryAuthKey"), recoverySalt),
      toB64(recoverySalt),
      now,
      now,
      user.id,
    )
    .run();

  await audit.record(env, user.id, "recovery_key_replaced");
  return json({ ok: true });
}

// --- last resort ------------------------------------------------------------

/**
 * POST /api/account/reset/request
 *
 * For an account whose master password *and* Recovery Key are both gone. This
 * cannot restore anything — it destroys the vault so the address can be used
 * again. Always answers 200, so it cannot be used to probe for accounts.
 */
export async function requestReset(
  env: Env,
  request: Request,
  ctx: ExecutionContext,
): Promise<Response> {
  const body = await readJson(request);
  const email = requireString(body, "email", { max: 320 });
  const user = await env.DB.prepare(`SELECT id, email_enc FROM users WHERE email_index = ?`)
    .bind(await emailIndex(env, email))
    .first<{ id: string; email_enc: string }>();

  if (user) {
    const token = await issueToken(env, user.id, "reset_account", RESET_TOKEN_MS);
    const address = await open(env, user.email_enc, `user.email:${user.id}`);
    ctx.waitUntil(mail.sendAccountReset(env, address, `${env.APP_URL}/app/?reset=${token}`));
  }

  return json({
    ok: true,
    message: "If that address has an account, an email is on its way.",
  });
}

/** POST /api/account/reset/confirm — wipes the vault and re-keys the account. */
export async function confirmReset(env: Env, request: Request): Promise<Response> {
  const body = await readJson(request);
  const userId = await consumeToken(env, requireString(body, "token", { max: 128 }), "reset_account");

  const salt = randomBytes(16);
  const recoverySalt = randomBytes(16);
  const now = Date.now();

  await env.DB.batch([
    // The items are unreadable without the old key anyway; removing them keeps
    // the promise that a reset really is a fresh start.
    env.DB.prepare(`DELETE FROM items WHERE user_id = ?`).bind(userId),
    env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(userId),
    env.DB.prepare(
      `UPDATE users SET auth_hash = ?, server_salt = ?, kdf_iterations = ?, protected_key = ?,
                        recovery_wrap = ?, recovery_hash = ?, recovery_salt = ?,
                        recovery_created_at = ?, email_verified = 1, totp_enabled = 0,
                        totp_secret_enc = NULL, totp_backup_enc = NULL, updated_at = ?
         WHERE id = ?`,
    ).bind(
      await hashAuthKey(env, requireKey(body, "authKey"), salt),
      toB64(salt),
      requireIterations(body),
      await seal(env, requireBlob(body, "protectedKey"), `user.protected_key:${userId}`),
      await seal(env, requireBlob(body, "recoveryWrap"), `user.recovery_wrap:${userId}`),
      await hashAuthKey(env, requireKey(body, "recoveryAuthKey"), recoverySalt),
      toB64(recoverySalt),
      now,
      now,
      userId,
    ),
  ]);

  await audit.record(env, userId, "account_reset");
  return json({ ok: true });
}

// --- second factor ----------------------------------------------------------

/** POST /api/account/totp/start — mints a secret but does not arm it yet. */
export async function totpStart(env: Env, session: Session): Promise<Response> {
  const user = await loadUser(env, session.userId);
  if (user.totp_enabled === 1) throw conflict("Two-factor authentication is already on.");

  const secret = generateTotpSecret();
  await env.DB.prepare(`UPDATE users SET totp_secret_enc = ?, updated_at = ? WHERE id = ?`)
    .bind(await seal(env, secret, `user.totp:${user.id}`), Date.now(), user.id)
    .run();

  const email = await open(env, user.email_enc, `user.email:${user.id}`);
  const label = encodeURIComponent(`KalmPass:${email}`);
  const uri = `otpauth://totp/${label}?secret=${secret}&issuer=KalmPass&algorithm=SHA1&digits=6&period=30`;
  return json({ secret, uri });
}

/** POST /api/account/totp/enable — arms it only once a live code proves it works. */
export async function totpEnable(env: Env, request: Request, session: Session): Promise<Response> {
  const user = await loadUser(env, session.userId);
  if (user.totp_enabled === 1) throw conflict("Two-factor authentication is already on.");
  if (!user.totp_secret_enc) throw badRequest("Start enrolment first.");

  const code = requireString(await readJson(request), "code", { max: 10 });
  const secret = await open(env, user.totp_secret_enc, `user.totp:${user.id}`);
  if (!(await verifyTotp(secret, code))) throw unauthorized("That code was not accepted.");

  // Shown once, then only their hashes are kept — we cannot recover them later.
  const codes = Array.from({ length: RECOVERY_CODE_COUNT }, () => toB64Url(randomBytes(9)));
  const hashed = await Promise.all(codes.map((c) => pepper(env, `backup:${user.id}:${c}`)));

  await env.DB.prepare(
    `UPDATE users SET totp_enabled = 1, totp_backup_enc = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(await seal(env, JSON.stringify(hashed), `user.backup:${user.id}`), Date.now(), user.id)
    .run();

  await audit.record(env, user.id, "totp_enabled");
  return json({ ok: true, backupCodes: codes });
}

/** POST /api/account/totp/disable — requires the master password again. */
export async function totpDisable(env: Env, request: Request, session: Session): Promise<Response> {
  const user = await loadUser(env, session.userId);
  await assertMasterPassword(env, user, await readJson(request));

  await env.DB.prepare(
    `UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_backup_enc = NULL,
                      updated_at = ? WHERE id = ?`,
  )
    .bind(Date.now(), user.id)
    .run();

  await audit.record(env, user.id, "totp_disabled");
  return json({ ok: true });
}

/** Single-use: a code that works is removed before the login is allowed through. */
async function consumeBackupCode(env: Env, user: UserRow, code: string): Promise<boolean> {
  if (!user.totp_backup_enc) return false;

  let stored: string[];
  try {
    stored = JSON.parse(await open(env, user.totp_backup_enc, `user.backup:${user.id}`));
  } catch {
    return false;
  }

  const candidate = await pepper(env, `backup:${user.id}:${code.trim()}`);
  let matched = false;
  const remaining: string[] = [];
  for (const entry of stored) {
    if (!matched && timingSafeEqual(fromB64(entry), fromB64(candidate))) matched = true;
    else remaining.push(entry);
  }
  if (!matched) return false;

  await env.DB.prepare(`UPDATE users SET totp_backup_enc = ?, updated_at = ? WHERE id = ?`)
    .bind(
      await seal(env, JSON.stringify(remaining), `user.backup:${user.id}`),
      Date.now(),
      user.id,
    )
    .run();
  return true;
}

// --- devices and activity ---------------------------------------------------

/** GET /api/account/sessions */
export async function listSessions(env: Env, session: Session): Promise<Response> {
  const { results } = await env.DB.prepare(
    `SELECT id, created_at, last_seen_at, expires_at, label_enc
       FROM sessions WHERE user_id = ? AND scope = 'full' ORDER BY last_seen_at DESC`,
  )
    .bind(session.userId)
    .all<{
      id: string;
      created_at: number;
      last_seen_at: number;
      expires_at: number;
      label_enc: string | null;
    }>();

  return json({
    sessions: await Promise.all(
      results.map(async (row) => ({
        current: row.id === session.id,
        createdAt: row.created_at,
        lastSeenAt: row.last_seen_at,
        expiresAt: row.expires_at,
        label: row.label_enc ? await open(env, row.label_enc, `session.label:${row.id}`) : "unknown",
      })),
    ),
  });
}

/** DELETE /api/account/sessions — sign out everywhere else. */
export async function revokeOtherSessions(env: Env, session: Session): Promise<Response> {
  const revoked = await destroyOtherSessions(env, session);
  await audit.record(env, session.userId, "sessions_revoked");
  return json({ ok: true, revoked });
}

/** GET /api/account/activity */
export async function activity(env: Env, session: Session): Promise<Response> {
  return json({ events: await audit.list(env, session.userId) });
}

/** DELETE /api/account — irreversible, and gated on the master password. */
export async function deleteAccount(
  env: Env,
  request: Request,
  session: Session,
): Promise<Response> {
  const user = await loadUser(env, session.userId);
  const body = await readJson(request);
  await assertMasterPassword(env, user, body);
  if (requireString(body, "confirm", { max: 32 }) !== "DELETE") {
    throw badRequest("Type DELETE to confirm.");
  }

  await env.DB.batch([
    env.DB.prepare(`DELETE FROM items WHERE user_id = ?`).bind(user.id),
    env.DB.prepare(`DELETE FROM sessions WHERE user_id = ?`).bind(user.id),
    env.DB.prepare(`DELETE FROM tokens WHERE user_id = ?`).bind(user.id),
    env.DB.prepare(`DELETE FROM audit WHERE user_id = ?`).bind(user.id),
    env.DB.prepare(`DELETE FROM users WHERE id = ?`).bind(user.id),
  ]);

  return json({ ok: true }, { headers: { "set-cookie": clearedCookie() } });
}

/** A readable device name for the activity log, from an unreadable user agent. */
export function describeAgent(request: Request): string {
  const agent = request.headers.get("user-agent") ?? "";
  const browser = /Edg\//.test(agent)
    ? "Edge"
    : /OPR\//.test(agent)
      ? "Opera"
      : /Chrome\//.test(agent)
        ? "Chrome"
        : /Firefox\//.test(agent)
          ? "Firefox"
          : /Safari\//.test(agent)
            ? "Safari"
            : "Unknown browser";
  const platform = /Windows/.test(agent)
    ? "Windows"
    : /Android/.test(agent)
      ? "Android"
      : /iPhone|iPad/.test(agent)
        ? "iOS"
        : /Mac OS X/.test(agent)
          ? "macOS"
          : /Linux/.test(agent)
            ? "Linux"
            : "";
  return [browser, platform].filter(Boolean).join(" on ");
}
