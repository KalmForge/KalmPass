/**
 * Server-side primitives.
 *
 * Note what is *not* here: nothing in this file can decrypt a vault. The Worker
 * only ever hashes login tokens and hands out session identifiers. Vault
 * encryption lives entirely in `public/js/crypto.js`, in the browser.
 */

const enc = new TextEncoder();

export function toB64(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

export function fromB64(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function toB64Url(bytes: Uint8Array): string {
  return toB64(bytes).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomBytes(n: number): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(n));
}

/** URL-safe, 256 bits of entropy. Used for row ids and session tokens. */
export function randomToken(): string {
  return toB64Url(randomBytes(32));
}

export function randomId(): string {
  return toB64Url(randomBytes(16));
}

export async function sha256(input: string | Uint8Array): Promise<Uint8Array> {
  const data = typeof input === "string" ? enc.encode(input) : input;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", data as BufferSource));
}

export async function sha256Hex(input: string | Uint8Array): Promise<string> {
  const d = await sha256(input);
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Iterations applied on top of the client's own KDF before anything is stored. */
export const SERVER_PBKDF2_ITERATIONS = 100_000;

export async function pbkdf2(
  secret: Uint8Array,
  salt: Uint8Array,
  iterations = SERVER_PBKDF2_ITERATIONS,
): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey("raw", secret as BufferSource, "PBKDF2", false, [
    "deriveBits",
  ]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: salt as BufferSource, iterations },
    key,
    256,
  );
  return new Uint8Array(bits);
}

/**
 * Compares in time independent of where the first difference falls, so a
 * remote attacker cannot walk a hash out byte by byte.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] as number) ^ (b[i] as number);
  return diff === 0;
}
