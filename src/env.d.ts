declare global {
  interface Env {
    DB: D1Database;
    ASSETS: Fetcher;

    /** Cloudflare Email Sending. Absent until the domain is onboarded. */
    EMAIL?: { send(message: EmailMessagePayload): Promise<unknown> };

    /** 32+ random bytes, base64. `npx wrangler secret put SERVER_KEY`. */
    SERVER_KEY: string;

    /** Public origin, used to build links in emails. */
    APP_URL: string;
    /** From address for transactional mail. Must be on an onboarded domain. */
    MAIL_FROM: string;
    MAIL_FROM_NAME: string;

    /** "false" closes registration entirely. */
    ALLOW_SIGNUP: string;
    /** Optional invite code gating registration while in private beta. */
    SIGNUP_TOKEN?: string;

    /** Whoever signs in as this address gets the admin dashboard. */
    ADMIN_EMAIL?: string;
    /** Display only, for the revenue figure on that dashboard. */
    PRO_PRICE?: string;
    PRO_CURRENCY?: string;

    STRIPE_SECRET_KEY?: string;
    STRIPE_WEBHOOK_SECRET?: string;
    STRIPE_PRICE_ID?: string;
  }

  interface EmailMessagePayload {
    to: string;
    from: { email: string; name?: string };
    subject: string;
    html: string;
    text: string;
    replyTo?: { email: string; name?: string };
  }
}

export {};
