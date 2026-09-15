/** What each plan allows. Enforced server-side, never trusted from the client. */

export interface Plan {
  id: "free" | "pro";
  name: string;
  /** null means unlimited. */
  items: number | null;
  devices: number | null;
  breachCheck: boolean;
}

/**
 * Items are unlimited on both plans, deliberately.
 *
 * Capping them looks like the obvious lever and is the wrong one. Everybody
 * arrives by importing an export from somewhere else, so an item cap blocks the
 * migration that acquires the customer in the first place, and it blocks it
 * hardest for the people with the most passwords, who are exactly the people
 * most likely to pay. Devices are the honest lever: you meet the limit when you
 * add your phone, by which point you already depend on the thing.
 */
export const PLANS: Record<string, Plan> = {
  free: { id: "free", name: "Free", items: null, devices: 2, breachCheck: false },
  pro: { id: "pro", name: "Pro", items: null, devices: null, breachCheck: true },
};

/**
 * A subscription that has lapsed drops back to Free limits, but never deletes
 * anything. An over-quota vault stops taking new items rather than losing any.
 * Nobody should lose passwords because a card expired.
 */
export function planFor(plan: string, status: string | null): Plan {
  const active = status === null || ["active", "trialing", "past_due"].includes(status);
  return (active && PLANS[plan]) || PLANS.free!;
}
