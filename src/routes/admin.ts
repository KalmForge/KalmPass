/**
 * The operator's dashboard.
 *
 * Read this constraint before adding anything here: an admin endpoint must not
 * become a hole in the zero-knowledge guarantee. Everything below counts rows,
 * reads plan state, and decrypts the account email so there is somebody to
 * contact. None of it touches `items.data`, and none of it can, because the
 * server has no key that opens a vault.
 *
 * If you ever find yourself wanting to add "show me what a customer has saved",
 * the answer is that it is not possible, and that is the product working.
 */

import { loadUser } from "../accounts";
import { fromB64, timingSafeEqual } from "../crypto";
import { json, notFound } from "../http";
import { emailIndex, open } from "../serverkey";
import type { Session } from "../sessions";

const DAY = 86_400_000;
const WINDOW_DAYS = 30;

/**
 * Admin is whoever signs in as ADMIN_EMAIL, so there is no second credential to
 * manage and the door is protected by the master password and the second factor
 * already on that account.
 *
 * A non-admin gets 404 rather than 403, so the endpoint does not confirm its own
 * existence to someone poking at the API.
 */
async function assertAdmin(env: Env, session: Session): Promise<void> {
  if (!env.ADMIN_EMAIL) throw notFound();

  const user = await loadUser(env, session.userId);
  const expected = await emailIndex(env, env.ADMIN_EMAIL);
  if (!timingSafeEqual(fromB64(user.email_index), fromB64(expected))) throw notFound();
}

interface AccountRow {
  id: string;
  email_enc: string;
  plan: string;
  plan_status: string | null;
  plan_period_end: number | null;
  email_verified: number;
  created_at: number;
  last_login_at: number | null;
}

/**
 * D1 types a batch entry as possibly absent. Aggregate queries always return
 * exactly one row, so these two narrow that away in one place rather than
 * scattering non-null assertions through the handler.
 */
const firstRow = <T>(result: D1Result<unknown> | undefined): T =>
  (result?.results?.[0] ?? {}) as T;

const allRows = <T>(result: D1Result<unknown> | undefined): T[] =>
  (result?.results ?? []) as T[];

/** GET /api/admin/overview */
export async function overview(env: Env, session: Session): Promise<Response> {
  await assertAdmin(env, session);

  const now = Date.now();
  const since = now - WINDOW_DAYS * DAY;

  const [totals, items, sessions, locked, signups, accounts, itemCounts] = await env.DB.batch([
    env.DB.prepare(
      `SELECT COUNT(*) AS accounts,
              COALESCE(SUM(email_verified), 0) AS verified,
              COALESCE(SUM(CASE WHEN plan = 'pro' THEN 1 ELSE 0 END), 0) AS pro,
              COALESCE(SUM(CASE WHEN plan_status = 'past_due' THEN 1 ELSE 0 END), 0) AS past_due,
              COALESCE(SUM(CASE WHEN plan_status = 'canceled' THEN 1 ELSE 0 END), 0) AS canceled,
              COALESCE(SUM(CASE WHEN created_at > ?1 THEN 1 ELSE 0 END), 0) AS new_window,
              COALESCE(SUM(CASE WHEN last_login_at > ?1 THEN 1 ELSE 0 END), 0) AS active_window
         FROM users`,
    ).bind(since),

    env.DB.prepare(
      `SELECT COUNT(*) AS total,
              COALESCE(SUM(CASE WHEN deleted_at IS NULL THEN 1 ELSE 0 END), 0) AS live
         FROM items`,
    ),

    env.DB.prepare(`SELECT COUNT(*) AS n FROM sessions WHERE expires_at > ?`).bind(now),

    env.DB.prepare(`SELECT COUNT(*) AS n FROM throttle WHERE locked_until > ?`).bind(now),

    // Grouped in SQL rather than pulled row by row, so this stays cheap as the
    // account table grows.
    env.DB.prepare(
      `SELECT strftime('%Y-%m-%d', created_at / 1000, 'unixepoch') AS day, COUNT(*) AS n
         FROM users WHERE created_at > ? GROUP BY day ORDER BY day`,
    ).bind(since),

    env.DB.prepare(
      `SELECT id, email_enc, plan, plan_status, plan_period_end, email_verified,
              created_at, last_login_at
         FROM users ORDER BY created_at DESC LIMIT 100`,
    ),

    env.DB.prepare(
      `SELECT user_id, COUNT(*) AS n FROM items WHERE deleted_at IS NULL GROUP BY user_id`,
    ),
  ]);

  const perUser = new Map<string, number>();
  for (const row of allRows<{ user_id: string; n: number }>(itemCounts)) {
    perUser.set(row.user_id, row.n);
  }

  const rows = allRows<AccountRow>(accounts);
  const listed = await Promise.all(
    rows.map(async (row) => ({
      // Decrypting the address is the one piece of customer data here, and it
      // exists so support has somebody to write to.
      email: await open(env, row.email_enc, `user.email:${row.id}`),
      plan: row.plan,
      planStatus: row.plan_status,
      planPeriodEnd: row.plan_period_end,
      verified: row.email_verified === 1,
      createdAt: row.created_at,
      lastLoginAt: row.last_login_at,
      items: perUser.get(row.id) ?? 0,
    })),
  );

  const counts = firstRow<Record<string, number>>(totals);
  const itemTotals = firstRow<Record<string, number>>(items);
  const price = Number(env.PRO_PRICE ?? "0");
  const interval = env.PRO_INTERVAL === "month" ? "month" : "year";
  // Normalised to a month, so an annual plan does not read twelve times high.
  const monthlyPrice = interval === "year" ? price / 12 : price;

  // Every day in the window is present, including the empty ones, so the chart
  // shows real gaps instead of silently compressing them.
  const byDay = new Map(
    allRows<{ day: string; n: number }>(signups).map((row) => [row.day, row.n]),
  );
  const series = Array.from({ length: WINDOW_DAYS }, (_, i) => {
    const date = new Date(now - (WINDOW_DAYS - 1 - i) * DAY);
    const day = date.toISOString().slice(0, 10);
    return { day, count: byDay.get(day) ?? 0 };
  });

  return json({
    generatedAt: now,
    windowDays: WINDOW_DAYS,
    currency: env.PRO_CURRENCY ?? "GBP",
    price,
    interval,
    totals: {
      accounts: counts.accounts ?? 0,
      verified: counts.verified ?? 0,
      pro: counts.pro ?? 0,
      free: (counts.accounts ?? 0) - (counts.pro ?? 0),
      pastDue: counts.past_due ?? 0,
      canceled: counts.canceled ?? 0,
      newInWindow: counts.new_window ?? 0,
      activeInWindow: counts.active_window ?? 0,
      itemsLive: itemTotals.live ?? 0,
      itemsTotal: itemTotals.total ?? 0,
      liveSessions: firstRow<Record<string, number>>(sessions).n ?? 0,
      lockedOut: firstRow<Record<string, number>>(locked).n ?? 0,
      // Paying accounts only. `past_due` is excluded because that money has not
      // arrived, and counting it would flatter the figure.
      mrr: (counts.pro ?? 0) * monthlyPrice,
      arr: (counts.pro ?? 0) * monthlyPrice * 12,
    },
    signups: series,
    accounts: listed,
  });
}
