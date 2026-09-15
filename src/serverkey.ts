/**
 * The server envelope: the second of the two encryption layers.
 *
 * Everything persisted to D1 passes through here first. The key material is
 * derived from SERVER_KEY, a Cloudflare Worker secret, which means it lives in
 * a different system from the database it protects. Read access to D1, a
 * leaked backup, a compromised API token, a subpoena served on the storage
 * layer. Yields ciphertext and nothing else.
 *
 * SERVER_KEY is not a backdoor into your vault. Even holding it, the contents
 * of `items.data` are still AES-GCM ciphertext under a key that only your
 * master password can unwrap.
 */

import { fromB64, randomBytes, toB64 } from "./crypto";
import { HttpError } from "./http";

const enc = new TextEncoder();
const dec = new TextDecoder();

interface ServerKeys {
  /** Wraps every at-rest value. */
  envelope: CryptoKey;
  /** Peppers password hashes and session tokens so D1 alone cannot be cracked. */
  pepper: CryptoKey;
  /** Turns an email address into a lookup token that cannot be reversed. */
  emailIndex: CryptoKey;
}

// Derivation is a few milliseconds but runs on every request otherwise, so it
// is memoised for the lifetime of the isolate. Keyed by the secret itself, so a
// rotated secret can never be served from a stale entry.
const cache = new Map<string, Promise<ServerKeys>>();

async function derive(secret: string): Promise<ServerKeys> {
  let raw: Uint8Array;
  try {
    raw = fromB64(secret);
  } catch {
    throw new HttpError(500, "misconfigured", "SERVER_KEY is not valid base64.");
  }
  if (raw.length < 32) {
    throw new HttpError(500, "misconfigured", "SERVER_KEY must be at least 32 bytes.");
  }

  const ikm = await crypto.subtle.importKey("raw", raw as BufferSource, "HKDF", false, [
    "deriveBits",
  ]);
  const branch = async (label: string) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        {
          name: "HKDF",
          hash: "SHA-256",
          salt: new Uint8Array(0) as BufferSource,
          info: enc.encode(label) as BufferSource,
        },
        ikm,
        256,
      ),
    );

  const [envelopeBits, pepperBits, emailBits] = await Promise.all([
    branch("kalmpass/v1/envelope"),
    branch("kalmpass/v1/pepper"),
    branch("kalmpass/v1/email-index"),
  ]);

  const hmac = (bits: Uint8Array) =>
    crypto.subtle.importKey("raw", bits as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, [
      "sign",
    ]);

  const [envelope, pepper, emailIndex] = await Promise.all([
    crypto.subtle.importKey("raw", envelopeBits as BufferSource, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]),
    hmac(pepperBits),
    hmac(emailBits),
  ]);

  return { envelope, pepper, emailIndex };
}

function keys(env: Env): Promise<ServerKeys> {
  const secret = env.SERVER_KEY;
  if (!secret) {
    throw new HttpError(
      500,
      "misconfigured",
      "SERVER_KEY is not set. Run: npx wrangler secret put SERVER_KEY",
    );
  }
  let pending = cache.get(secret);
  if (!pending) {
    pending = derive(secret);
    cache.set(secret, pending);
  }
  return pending;
}

/**
 * `context` is bound into the ciphertext as additional authenticated data, so a
 * blob cannot be lifted out of one row and replayed into another, an attacker
 * with write access to D1 cannot swap your vault key for someone else's.
 */
export async function seal(env: Env, plaintext: string, context: string): Promise<string> {
  const { envelope } = await keys(env);
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv as BufferSource, additionalData: enc.encode(context) as BufferSource },
      envelope,
      enc.encode(plaintext) as BufferSource,
    ),
  );
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toB64(out);
}

export async function open(env: Env, sealed: string, context: string): Promise<string> {
  const { envelope } = await keys(env);
  const raw = fromB64(sealed);
  if (raw.length < 13) throw new HttpError(500, "corrupt", "Stored value is malformed.");
  try {
    const plain = await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: raw.subarray(0, 12) as BufferSource,
        additionalData: enc.encode(context) as BufferSource,
      },
      envelope,
      raw.subarray(12) as BufferSource,
    );
    return dec.decode(plain);
  } catch {
    // Either SERVER_KEY has been rotated without re-encrypting, or the row was
    // tampered with. Both are fatal and must not be papered over.
    throw new HttpError(
      500,
      "decrypt_failed",
      "A stored value could not be decrypted. SERVER_KEY may have changed.",
    );
  }
}

async function mac(key: CryptoKey, data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? enc.encode(data) : data;
  return toB64(new Uint8Array(await crypto.subtle.sign("HMAC", key, bytes as BufferSource)));
}

/** Deterministic, irreversible lookup token for an email address. */
export async function emailIndex(env: Env, email: string): Promise<string> {
  const { emailIndex: key } = await keys(env);
  return mac(key, normalizeEmail(email));
}

/** Peppers a value so that D1 contents alone cannot be brute-forced offline. */
export async function pepper(env: Env, data: Uint8Array | string): Promise<string> {
  const { pepper: key } = await keys(env);
  return mac(key, data);
}

export function normalizeEmail(email: string): string {
  return email.trim().toLowerCase();
}
