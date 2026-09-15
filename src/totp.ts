/**
 * RFC 6238 TOTP, used for the optional second factor on the login itself.
 *
 * (The authenticator codes you *store in the vault* are a separate thing and are
 * computed in the browser — their seeds are never sent here in the clear.)
 */

import { timingSafeEqual } from "./crypto";

const STEP_SECONDS = 30;
const DIGITS = 6;
/** Accept the neighbouring steps so a slightly skewed phone clock still works. */
const DRIFT_STEPS = 1;

const ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input: string): Uint8Array {
  const clean = input.toUpperCase().replace(/=+$/, "").replace(/\s+/g, "");
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const char of clean) {
    const idx = ALPHABET.indexOf(char);
    if (idx === -1) throw new Error("Invalid base32 character.");
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = "";
  for (const byte of bytes) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

async function codeForCounter(secret: Uint8Array, counter: number): Promise<string> {
  const buf = new ArrayBuffer(8);
  const view = new DataView(buf);
  // Counters exceed 32 bits only in the year 6000-odd, but split the write
  // anyway rather than rely on a lossy Number bit-shift.
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const key = await crypto.subtle.importKey(
    "raw",
    secret as BufferSource,
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", key, buf));

  const offset = (mac[mac.length - 1] as number) & 0x0f;
  const binary =
    (((mac[offset] as number) & 0x7f) << 24) |
    (((mac[offset + 1] as number) & 0xff) << 16) |
    (((mac[offset + 2] as number) & 0xff) << 8) |
    ((mac[offset + 3] as number) & 0xff);

  return (binary % 10 ** DIGITS).toString().padStart(DIGITS, "0");
}

/** Constant-time across the accepted window, so timing cannot reveal the offset. */
export async function verifyTotp(
  base32Secret: string,
  submitted: string,
  now = Date.now(),
): Promise<boolean> {
  const code = submitted.replace(/\D/g, "");
  if (code.length !== DIGITS) return false;

  const secret = base32Decode(base32Secret);
  const counter = Math.floor(now / 1000 / STEP_SECONDS);
  const encoder = new TextEncoder();
  const target = encoder.encode(code);

  let match = false;
  for (let drift = -DRIFT_STEPS; drift <= DRIFT_STEPS; drift++) {
    const candidate = await codeForCounter(secret, counter + drift);
    if (timingSafeEqual(encoder.encode(candidate), target)) match = true;
  }
  return match;
}

export function generateTotpSecret(): string {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}
