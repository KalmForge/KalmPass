/** What each plan allows. Enforced server-side, never trusted from the client. */

export interface Plan {
  id: "free" | "pro";
  name: string;
  /** null means unlimited. */
  items: number | null;
  devices: number | null;
  breachCheck: boolean;
}

export const PLANS: Record<string, Plan> = {
  free: { id: "free", name: "Free", items: 50, devices: 2, breachCheck: false },
  pro: { id: "pro", name: "Pro", items: null, devices: null, breachCheck: true },
};

/**
 * A subscription that has lapsed drops back to Free limits, but never deletes
 * anything, an over-quota vault becomes read-only rather than losing items.
 * Nobody should lose passwords because a card expired.
 */
export function planFor(plan: string, status: string | null): Plan {
  const active = status === null || ["active", "trialing", "past_due"].includes(status);
  return (active && PLANS[plan]) || PLANS.free!;
}

export const isUnlimited = (value: number | null): value is null => value === null;
