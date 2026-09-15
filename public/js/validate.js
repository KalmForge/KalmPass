/** Shared input checks, so the same rule is not written out in three places. */

/**
 * Deliberately loose. Anything stricter rejects addresses that are perfectly
 * legal, and the only real test of an address is whether mail reaches it, which
 * is what the confirmation email is for.
 */
const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

export const isEmail = (value) => EMAIL.test((value ?? "").trim());
