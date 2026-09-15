/**
 * Authenticator codes for items in the vault (RFC 6238).
 *
 * The seed is stored inside the item's encrypted blob and the code is computed
 * here, in the tab. The server never sees a seed and never computes a code, so
 * this second factor stays a genuinely separate secret from the password beside
 * it, which is the entire point of having one.
 */

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

function base32Decode(input) {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/[\s-]+/g, "");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of clean) {
    const index = ALPHABET.indexOf(char);
    if (index === -1) throw new Error("That is not a valid authenticator key.");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  if (out.length === 0) throw new Error("That is not a valid authenticator key.");
  return new Uint8Array(out);
}

/**
 * Accepts either a bare base32 secret or a full `otpauth://` URI, because what
 * a site hands you is one or the other and retyping is where mistakes happen.
 */
export function parseTotp(input) {
  const text = (input ?? "").trim();
  if (!text) return null;

  if (text.toLowerCase().startsWith("otpauth://")) {
    const url = new URL(text);
    const params = url.searchParams;
    const secret = params.get("secret");
    if (!secret) throw new Error("That link has no secret in it.");
    return {
      secret: secret.replace(/\s+/g, ""),
      digits: Number(params.get("digits") ?? 6),
      period: Number(params.get("period") ?? 30),
      algorithm: (params.get("algorithm") ?? "SHA1").toUpperCase(),
      label: decodeURIComponent(url.pathname.replace(/^\//, "")),
    };
  }
  return { secret: text.replace(/[\s-]+/g, ""), digits: 6, period: 30, algorithm: "SHA1" };
}

const HASHES = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

export async function totpCode(config, now = Date.now()) {
  const { secret, digits = 6, period = 30, algorithm = "SHA1" } = config;
  const counter = Math.floor(now / 1000 / period);

  const buffer = new ArrayBuffer(8);
  const view = new DataView(buffer);
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const key = await crypto.subtle.importKey(
    "raw",
    base32Decode(secret),
    { name: "HMAC", hash: HASHES[algorithm] ?? "SHA-1" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buffer));

  const offset = mac[mac.length - 1] & 0x0f;
  const binary =
    ((mac[offset] & 0x7f) << 24) |
    ((mac[offset + 1] & 0xff) << 16) |
    ((mac[offset + 2] & 0xff) << 8) |
    (mac[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, "0");
}

/** Seconds left on the current code, for the countdown ring. */
export function secondsRemaining(period = 30, now = Date.now()) {
  return period - Math.floor(now / 1000) % period;
}

export function validateTotp(input) {
  try {
    const config = parseTotp(input);
    if (!config) return { ok: true, config: null };
    base32Decode(config.secret);
    return { ok: true, config };
  } catch (error) {
    return { ok: false, message: error.message };
  }
}
