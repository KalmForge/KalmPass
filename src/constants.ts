/** Shared tuning constants. The browser keeps its own copy in public/js/crypto.js. */

/**
 * PBKDF2-SHA256 rounds run in the browser to turn your master password into a
 * master key. OWASP's floor is 600,000; this sits comfortably above it and costs
 * roughly a second on unlock, which is a fair trade for a vault you open a few
 * times a day.
 */
export const DEFAULT_KDF_ITERATIONS = 1_000_000;
export const MIN_KDF_ITERATIONS = 600_000;
export const MAX_KDF_ITERATIONS = 10_000_000;

/** 32 bytes, base64, the size of every key and hash crossing the wire. */
export const KEY_BYTES = 32;

export const RECOVERY_CODE_COUNT = 10;
