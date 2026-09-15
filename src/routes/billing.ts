/**
 * Stripe billing.
 *
 * Called with `fetch` against Stripe's REST API rather than through their SDK.
 * A password manager is a bad place to take on a large dependency tree, and the
 * three calls we need are form posts.
 *
 * Nothing here can reach vault contents. The worst a billing bug can do is give
 * someone the wrong plan limits.
 */

import { type UserRow, loadUser } from "../accounts";
import * as audit from "../audit";
import { fromB64, timingSafeEqual } from "../crypto";
import { HttpError, badRequest, json, readJson, requireString } from "../http";
import { PLANS } from "../plans";
import { open, pepper, seal } from "../serverkey";
import type { Session } from "../sessions";

const STRIPE_API = "https://api.stripe.com/v1";
const encoder = new TextEncoder();

function requireStripe(env: Env): string {
  if (!env.STRIPE_SECRET_KEY) {
    throw new HttpError(503, "billing_disabled", "Billing is not configured on this instance.");
  }
  return env.STRIPE_SECRET_KEY;
}

/** Stripe speaks form encoding, including for nested fields like a[b][c]. */
async function stripe(
  env: Env,
  path: string,
  params: Record<string, string>,
): Promise<Record<string, any>> {
  const response = await fetch(`${STRIPE_API}${path}`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${requireStripe(env)}`,
      "content-type": "application/x-www-form-urlencoded",
      // Matches the version the webhook endpoint was created with, so API
      // responses and event payloads have the same shape. Managed Payments
      // needs 2025-03-31.basil or later, and periodEndOf below copes with the
      // renewal date having moved onto the subscription item in that release.
      "stripe-version": "2026-08-26.dahlia",
    },
    body: new URLSearchParams(params).toString(),
  });

  const payload = (await response.json()) as Record<string, any>;
  if (!response.ok) {
    console.error("stripe error", payload?.error);
    throw new HttpError(502, "stripe_error", payload?.error?.message ?? "Payment provider error.");
  }
  return payload;
}

// --- checkout ---------------------------------------------------------------

/** POST /api/billing/checkout */
export async function checkout(env: Env, request: Request, session: Session): Promise<Response> {
  requireStripe(env);
  if (!env.STRIPE_PRICE_ID) {
    throw new HttpError(503, "billing_disabled", "No subscription price is configured.");
  }

  const user = await loadUser(env, session.userId);
  if (user.email_verified !== 1) {
    // Taking money from an address nobody has confirmed invites chargebacks and
    // leaves us unable to reach the customer.
    throw new HttpError(403, "email_unverified", "Confirm your email address before subscribing.");
  }
  if (user.plan === "pro" && user.plan_status === "active") {
    throw new HttpError(409, "already_subscribed", "You are already on Pro.");
  }

  const email = await open(env, user.email_enc, `user.email:${user.id}`);
  const customerId = await existingCustomerId(env, user);

  const params: Record<string, string> = {
    mode: "subscription",
    "line_items[0][price]": env.STRIPE_PRICE_ID,
    "line_items[0][quantity]": "1",
    success_url: `${env.APP_URL}/app/?billing=success`,
    cancel_url: `${env.APP_URL}/app/?billing=cancelled`,
    client_reference_id: user.id,
    allow_promotion_codes: "true",
    "metadata[user_id]": user.id,
    "subscription_data[metadata][user_id]": user.id,
  };

  // Reusing the customer keeps one billing history per account rather than a new
  // customer record every time somebody opens the upgrade page.
  if (customerId) params.customer = customerId;
  else params.customer_email = email;

  const checkoutSession = await stripe(env, "/checkout/sessions", params);
  return json({ url: checkoutSession.url });
}

/** POST /api/billing/portal. Cards, invoices, cancellation. */
export async function portal(env: Env, session: Session): Promise<Response> {
  const user = await loadUser(env, session.userId);
  const customerId = await existingCustomerId(env, user);
  if (!customerId) throw new HttpError(409, "no_subscription", "There is nothing to manage yet.");

  const portalSession = await stripe(env, "/billing_portal/sessions", {
    customer: customerId,
    return_url: `${env.APP_URL}/app/`,
  });
  return json({ url: portalSession.url });
}

const existingCustomerId = async (env: Env, user: UserRow): Promise<string | null> =>
  user.stripe_customer_enc
    ? open(env, user.stripe_customer_enc, `user.stripe_customer:${user.id}`)
    : null;

// --- webhook ----------------------------------------------------------------

/**
 * POST /api/billing/webhook
 *
 * Unauthenticated by necessity. Stripe has no session, so the signature is the
 * only thing standing between this endpoint and anyone who wants a free Pro
 * plan. It is verified before the body is parsed, and the timestamp is checked
 * so a captured request cannot be replayed later.
 */
export async function webhook(env: Env, request: Request): Promise<Response> {
  if (!env.STRIPE_WEBHOOK_SECRET) {
    throw new HttpError(503, "billing_disabled", "Billing is not configured.");
  }

  const raw = await request.text();
  const signature = request.headers.get("stripe-signature") ?? "";
  if (!(await verifySignature(env.STRIPE_WEBHOOK_SECRET, raw, signature))) {
    throw new HttpError(400, "bad_signature", "Signature verification failed.");
  }

  let event: Record<string, any>;
  try {
    event = JSON.parse(raw);
  } catch {
    throw badRequest("Body must be valid JSON.");
  }

  const object = event?.data?.object ?? {};

  switch (event.type) {
    case "checkout.session.completed":
      await onCheckoutCompleted(env, object);
      break;

    case "customer.subscription.created":
    case "customer.subscription.updated":
    case "customer.subscription.deleted":
      await onSubscriptionChanged(env, object, event.type === "customer.subscription.deleted");
      break;

    case "invoice.payment_failed":
      await onPaymentFailed(env, object);
      break;

    default:
      // Stripe sends a great deal we do not care about; acknowledging keeps it
      // from retrying forever.
      break;
  }

  return json({ received: true });
}

async function verifySignature(secret: string, body: string, header: string): Promise<boolean> {
  const parts = Object.fromEntries(
    header
      .split(",")
      .map((part) => part.split("=", 2))
      .filter((pair): pair is [string, string] => pair.length === 2),
  );

  const timestamp = Number(parts.t);
  if (!Number.isFinite(timestamp)) return false;

  // Five minutes, matching Stripe's own recommendation. Outside that window a
  // replayed request is refused even with a valid signature.
  if (Math.abs(Date.now() / 1000 - timestamp) > 300) return false;
  if (!parts.v1) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, encoder.encode(`${timestamp}.${body}`)),
  );
  const expected = [...mac].map((b) => b.toString(16).padStart(2, "0")).join("");

  return timingSafeEqual(encoder.encode(expected), encoder.encode(parts.v1));
}

// --- event handlers ---------------------------------------------------------

async function findUser(env: Env, object: Record<string, any>): Promise<UserRow | null> {
  const fromMetadata = object?.metadata?.user_id;
  if (fromMetadata) {
    const row = await env.DB.prepare(`SELECT * FROM users WHERE id = ?`)
      .bind(fromMetadata)
      .first<UserRow>();
    if (row) return row;
  }

  const customer = typeof object?.customer === "string" ? object.customer : null;
  if (!customer) return null;

  return env.DB.prepare(`SELECT * FROM users WHERE stripe_customer_index = ?`)
    .bind(await pepper(env, `stripe:${customer}`))
    .first<UserRow>();
}

async function onCheckoutCompleted(env: Env, object: Record<string, any>): Promise<void> {
  const userId = object?.metadata?.user_id ?? object?.client_reference_id;
  const customer = typeof object?.customer === "string" ? object.customer : null;
  if (!userId || !customer) return;

  await env.DB.prepare(
    `UPDATE users SET stripe_customer_index = ?, stripe_customer_enc = ?,
                      plan = 'pro', plan_status = 'active', updated_at = ? WHERE id = ?`,
  )
    .bind(
      await pepper(env, `stripe:${customer}`),
      await seal(env, customer, `user.stripe_customer:${userId}`),
      Date.now(),
      userId,
    )
    .run();

  await audit.record(env, userId, "plan_changed", "Upgraded to Pro");
}

/**
 * Where the renewal date lives depends on the API version the webhook was
 * created with. Stripe moved it off the subscription and onto each subscription
 * item in the 2025-03-31 release, so read both rather than tying this Worker to
 * whichever version happened to be selected in the dashboard.
 */
function periodEndOf(subscription: Record<string, any>): number | null {
  const top = subscription?.current_period_end;
  if (typeof top === "number") return top * 1000;

  const items: any[] = subscription?.items?.data ?? [];
  const ends = items
    .map((item) => item?.current_period_end)
    .filter((value): value is number => typeof value === "number");

  // A subscription with several items renews when the earliest one does.
  return ends.length > 0 ? Math.min(...ends) * 1000 : null;
}

async function onSubscriptionChanged(
  env: Env,
  object: Record<string, any>,
  deleted: boolean,
): Promise<void> {
  const user = await findUser(env, object);
  if (!user) return;

  const status: string = deleted ? "canceled" : (object.status ?? "active");
  // `past_due` deliberately keeps Pro limits: the card can be fixed, and taking
  // someone's vault hostage over a failed payment is not a good look.
  const plan = deleted || ["canceled", "unpaid", "incomplete_expired"].includes(status)
    ? "free"
    : "pro";

  const periodEnd = periodEndOf(object);

  await env.DB.prepare(
    `UPDATE users SET plan = ?, plan_status = ?, plan_period_end = ?,
                      stripe_subscription_enc = ?, updated_at = ? WHERE id = ?`,
  )
    .bind(
      plan,
      status,
      periodEnd,
      typeof object.id === "string"
        ? await seal(env, object.id, `user.stripe_subscription:${user.id}`)
        : user.stripe_subscription_enc,
      Date.now(),
      user.id,
    )
    .run();

  await audit.record(
    env,
    user.id,
    "plan_changed",
    `${PLANS[plan]?.name ?? plan}${status === "active" ? "" : ` (${status})`}`,
  );
}

async function onPaymentFailed(env: Env, object: Record<string, any>): Promise<void> {
  const user = await findUser(env, object);
  if (!user) return;

  await env.DB.prepare(`UPDATE users SET plan_status = 'past_due', updated_at = ? WHERE id = ?`)
    .bind(Date.now(), user.id)
    .run();
  await audit.record(env, user.id, "plan_changed", "Payment failed");
}

export { fromB64 };
