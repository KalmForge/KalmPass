/**
 * KalmPass, the entire server.
 *
 * Two things are worth knowing before reading further:
 *
 *   1. This Worker cannot read anybody's vault. It stores ciphertext, checks a
 *      login verifier, and hands blobs back. Decryption happens in
 *      public/js/crypto.js, in the browser, under a key derived from a master
 *      password that is never transmitted.
 *
 *   2. There are no runtime dependencies. Every byte that runs here is in this
 *      repository, which keeps the supply chain for a password manager down to
 *      something one person can actually read.
 */

import { prune as pruneAudit } from "./audit";
import { HttpError, errorResponse, json, unauthorized } from "./http";
import * as account from "./routes/account";
import * as admin from "./routes/admin";
import * as billing from "./routes/billing";
import * as items from "./routes/items";
import * as passkeys from "./routes/passkeys";
import * as tools from "./routes/tools";
import { latestBackup, runBackup } from "./backup";
import { emailIndex } from "./serverkey";
import { type Session, purgeExpired, resolveSession } from "./sessions";

/**
 * Browsers attach `Origin` to every state-changing request and cannot be made to
 * forge it. Together with the SameSite=Strict cookie this closes CSRF twice.
 *
 * Stripe is the one caller that is not a browser and has no Origin to send; its
 * webhook carries a signature instead, which `billing.webhook` verifies before
 * it parses anything.
 */
const EXTENSION_ORIGIN = new RegExp("^(chrome-extension|moz-extension|safari-web-extension)://[A-Za-z0-9._-]+$");

/**
 * The mobile apps. Capacitor serves the app from these origins inside the
 * WebView: https on Android, its own scheme on iOS. Both use bearer tokens,
 * never the cookie, so CORS is granted to them without credentials.
 */
const APP_ORIGINS = new Set(["https://app.kalmpass.net", "capacitor://app.kalmpass.net"]);

function corsHeaders(origin: string): Record<string, string> {
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET, POST, PUT, DELETE",
    "access-control-allow-headers": "authorization, content-type",
    "access-control-max-age": "600",
    vary: "Origin",
  };
}

function withCors(response: Response, origin: string): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(corsHeaders(origin))) headers.set(k, v);
  // A cookie has no business going to an app that cannot use it.
  headers.delete("set-cookie");
  return new Response(response.body, { status: response.status, headers });
}

function assertSameOrigin(request: Request, url: URL): void {
  if (request.method === "GET" || request.method === "HEAD") return;
  if (url.pathname === "/api/billing/webhook") return;
  // A bearer token is sent deliberately by the caller rather than attached by
  // the browser, so a cross-site page cannot cause one to be used. CSRF is a
  // cookie problem, and this request is not using the cookie.
  if (request.headers.get("authorization")) return;
  const origin = request.headers.get("origin") ?? "";
  // The browser extensions sign in from their own origin. A web page cannot
  // claim one of these schemes, and the extensions send no cookie, so there is
  // nothing for a forged request to ride on.
  if (EXTENSION_ORIGIN.test(origin) || APP_ORIGINS.has(origin)) return;
  if (origin !== url.origin) {
    throw new HttpError(403, "bad_origin", "Cross-origin requests are not accepted.");
  }
}

/**
 * GET /api/health, for the uptime check in .github/workflows/uptime.yml.
 *
 * Proves the database answers and the server key is usable, and says how old
 * the last backup is. Nothing here identifies an account or reveals the key.
 */
async function health(env: Env): Promise<Response> {
  const checks = { database: false, serverKey: false, email: Boolean(env.EMAIL) };
  try {
    checks.database = (await env.DB.prepare("SELECT 1 AS ok").first<{ ok: number }>())?.ok === 1;
  } catch {
    /* reported as false */
  }
  try {
    await emailIndex(env, "health@kalmpass.net");
    checks.serverKey = true;
  } catch {
    /* reported as false */
  }
  const backup = await latestBackup(env).catch(() => null);
  const ok = checks.database && checks.serverKey;
  return json(
    {
      ok,
      checks,
      backupAgeHours: backup ? Math.floor((Date.now() - backup.createdAt) / 3_600_000) : null,
    },
    { status: ok ? 200 : 503 },
  );
}

async function requireSession(env: Env, request: Request): Promise<Session> {
  const session = await resolveSession(env, request);
  if (!session) throw unauthorized("Your session has expired. Sign in again.");
  return session;
}

async function route(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  url: URL,
): Promise<Response> {
  const { method } = request;
  const path = url.pathname.replace(/\/+$/, "") || "/api";

  // --- Public: getting in, and getting back in -----------------------------
  if (path === "/api/account/status" && method === "GET") return account.status(env);
  if (path === "/api/health" && method === "GET") return health(env);
  if (path === "/api/account/prelogin" && method === "POST") return account.prelogin(env, request);
  if (path === "/api/account/signup" && method === "POST") return account.signup(env, request, ctx);
  if (path === "/api/account/login" && method === "POST") return account.login(env, request, ctx);
  if (path === "/api/account/logout" && method === "POST") return account.logout(env, request);
  if (path === "/api/account/verify" && method === "POST") return account.verifyEmail(env, request);
  if (path === "/api/account/recover" && method === "POST") return account.recover(env, request);
  if (path === "/api/account/reset/request" && method === "POST") {
    return account.requestReset(env, request, ctx);
  }
  if (path === "/api/account/reset/confirm" && method === "POST") {
    return account.confirmReset(env, request);
  }
  if (path === "/api/billing/webhook" && method === "POST") return billing.webhook(env, request);
  if (path === "/api/account/passkey-login" && method === "POST") {
    return passkeys.login(env, request, ctx);
  }

  // --- Signed in -----------------------------------------------------------
  const session = await requireSession(env, request);

  // A recovery-scoped session exists to finish one task and may do nothing else,
  // so it is matched here and everything below is closed to it.
  if (path === "/api/account/recover/complete" && method === "POST") {
    return account.recoverComplete(env, request, session, ctx);
  }
  if (session.scope !== "full") {
    throw unauthorized("Finish setting your new master password first.");
  }

  if (path === "/api/account") {
    if (method === "GET") return account.me(env, session);
    if (method === "DELETE") return account.deleteAccount(env, request, session);
  }
  if (path === "/api/account/rekey" && method === "POST") {
    return account.rekey(env, request, session, ctx);
  }
  if (path === "/api/account/email" && method === "POST") {
    return account.changeEmail(env, request, session, ctx);
  }
  if (path === "/api/account/recovery-key/rotate" && method === "POST") {
    return account.rotateRecoveryKey(env, request, session);
  }
  if (path === "/api/account/resend-verification" && method === "POST") {
    return account.resendVerification(env, session, ctx);
  }
  if (path === "/api/account/totp/start" && method === "POST") return account.totpStart(env, session);
  if (path === "/api/account/totp/enable" && method === "POST") {
    return account.totpEnable(env, request, session);
  }
  if (path === "/api/account/totp/disable" && method === "POST") {
    return account.totpDisable(env, request, session);
  }
  if (path === "/api/account/passkeys") {
    if (method === "GET") return passkeys.list(env, session);
    if (method === "POST") return passkeys.register(env, request, session);
  }
  // Built from a string so the slashes need no escaping.
  const passkeyMatch = new RegExp("^/api/account/passkeys/([A-Za-z0-9_-]{1,64})$").exec(path);
  if (passkeyMatch && method === "DELETE") {
    return passkeys.remove(env, session, passkeyMatch[1] as string);
  }

  if (path === "/api/account/sessions") {
    if (method === "GET") return account.listSessions(env, session);
    if (method === "DELETE") return account.revokeOtherSessions(env, session);
  }
  if (path === "/api/account/activity" && method === "GET") return account.activity(env, session);

  if (path === "/api/admin/overview" && method === "GET") return admin.overview(env, session);
  if (path === "/api/admin/backup" && method === "POST") return admin.backupNow(env, session);

  if (path === "/api/billing/checkout" && method === "POST") {
    return billing.checkout(env, request, session);
  }
  if (path === "/api/billing/portal" && method === "POST") return billing.portal(env, session);

  // Fixed segments first, so they are never mistaken for an item id.
  if (path === "/api/items/bulk" && method === "POST") {
    return items.bulkCreate(env, request, session);
  }
  if (path === "/api/items/trash" && method === "DELETE") return items.emptyTrash(env, session);
  if (path === "/api/items") {
    if (method === "GET") return items.list(env, request, session);
    if (method === "POST") return items.create(env, request, session);
  }

  const itemMatch = /^\/api\/items\/([A-Za-z0-9_-]{1,64})(\/restore|\/purge)?$/.exec(path);
  if (itemMatch) {
    const id = itemMatch[1] as string;
    const action = itemMatch[2];
    if (!action && method === "PUT") return items.update(env, request, session, id);
    if (!action && method === "DELETE") return items.remove(env, session, id);
    if (action === "/restore" && method === "POST") return items.restore(env, session, id);
    if (action === "/purge" && method === "DELETE") return items.purge(env, session, id);
  }

  if (path === "/api/tools/exposed-passwords" && method === "POST") {
    return tools.exposedPasswordCheck(env, request, session);
  }

  return json({ error: "not_found", message: "No such endpoint." }, { status: 404 });
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // `run_worker_first` should mean only /api/* arrives here, but if routing
    // ever changes, fall through to the static site rather than 404.
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);

    const origin = request.headers.get("origin") ?? "";
    const app = APP_ORIGINS.has(origin);
    if (request.method === "OPTIONS") {
      return app
        ? new Response(null, { status: 204, headers: corsHeaders(origin) })
        : new Response(null, { status: 405 });
    }
    const respond = (response: Response) => (app ? withCors(response, origin) : response);

    try {
      assertSameOrigin(request, url);
      const response = await route(request, env, ctx, url);

      // Expired rows are dead weight; clear them on the way out occasionally
      // rather than making anybody wait for it.
      if (Math.random() < 0.02) ctx.waitUntil(purgeExpired(env).catch(() => {}));
      return respond(response);
    } catch (err) {
      return respond(errorResponse(err));
    }
  },

  /** Nightly housekeeping, so a quiet instance still tidies itself. */
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(
      Promise.all([purgeExpired(env), pruneAudit(env), runBackup(env)]).then(() => undefined),
    );
  },
} satisfies ExportedHandler<Env>;
