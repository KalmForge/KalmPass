/** Shared request validation, so the same rules are not written out per route. */

import { KEY_BYTES } from "./constants";
import { fromB64 } from "./crypto";
import { badRequest, requireString } from "./http";

/** A 32-byte base64 value, validated before it is allowed anywhere near the DB. */
export function requireKey(body: Record<string, unknown>, field: string): Uint8Array {
  const raw = requireString(body, field, { max: 128 });
  let bytes: Uint8Array;
  try {
    bytes = fromB64(raw);
  } catch {
    throw badRequest(`"${field}" must be base64.`);
  }
  if (bytes.length !== KEY_BYTES) throw badRequest(`"${field}" must decode to ${KEY_BYTES} bytes.`);
  return bytes;
}

/** base64(iv || ciphertext) produced by the browser. Opaque here, but bounded. */
export function requireBlob(
  body: Record<string, unknown>,
  field: string,
  max = 4096,
): string {
  const raw = requireString(body, field, { max });
  if (!/^[A-Za-z0-9+/]+={0,2}$/.test(raw)) throw badRequest(`"${field}" must be base64.`);
  if (raw.length < 24) throw badRequest(`"${field}" is too short to be valid ciphertext.`);
  return raw;
}

/** A WebAuthn credential id, which the browser gives us as base64url. */
export function requireCredentialId(body: Record<string, unknown>): string {
  const raw = requireString(body, "credentialId", { max: 512 });
  if (!/^[A-Za-z0-9_-]{16,512}$/.test(raw)) throw badRequest("That credential id is malformed.");
  return raw;
}
