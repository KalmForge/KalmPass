/**
 * Client-side cryptography. This is the part that matters.
 *
 * The master password is used here and nowhere else. It is never sent to the
 * server, never stored, and never written to disk. From it we derive a master
 * key, and from that two independent branches:
 *
 *     master password
 *          |  PBKDF2-SHA256, 1,000,000 rounds, salted with the account email
 *          v
 *      master key ----HKDF "enc"----> encryption key  (stays in this tab)
 *          |
 *          +---------HKDF "auth"---> auth key        (sent to the server)
 *
 * The branches are independent: the server holds the auth key's hash and can do
 * nothing with it but recognise a correct login. Deriving the encryption key
 * from it is not possible, so a fully compromised server still cannot read a
 * single item.
 *
 * Items are encrypted under a random vault key, which is wrapped twice, once by
 * the master password's encryption key, once by the Recovery Key. Either opens
 * the vault; we hold neither. That is what makes account recovery possible
 * without anyone escrowing a key on the customer's behalf.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export const DEFAULT_KDF_ITERATIONS = 1_000_000;

/**
 * The Recovery Key is 125 bits of uniform randomness, so it does not need the
 * master password's punishing round count to resist guessing. Nothing can
 * enumerate that space regardless.
 */
const RECOVERY_KDF_ITERATIONS = 200_000;

/** Item plaintext is padded to a multiple of this, so blob size says nothing. */
const PAD_BLOCK = 256;

// --- encoding ---------------------------------------------------------------

export function toB64(bytes) {
  let binary = "";
  const chunk = 0x8000; // Chunked, or a large vault blows the argument limit.
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

export function fromB64(b64) {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export const normalizeEmail = (email) => email.trim().toLowerCase();

// --- key derivation ---------------------------------------------------------

/**
 * The slow step. A million rounds costs roughly a second on a laptop, which is
 * the point: it multiplies the cost of every guess in an offline attack by the
 * same factor.
 */
async function stretch(secret, salt, iterations) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: encoder.encode(salt), iterations },
    material,
    256,
  );
  return new Uint8Array(bits);
}

async function hkdf(masterKeyBytes, label, length = 32) {
  const key = await crypto.subtle.importKey("raw", masterKeyBytes, "HKDF", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: encoder.encode(label) },
    key,
    length * 8,
  );
  return new Uint8Array(bits);
}

/**
 * Splits a stretched secret into the two things the app needs: a key that stays
 * here, and a token the server is allowed to see.
 */
async function branch(masterKey, label) {
  const [encBits, authBits] = await Promise.all([
    hkdf(masterKey, `${label}/enc`),
    hkdf(masterKey, `${label}/auth`),
  ]);
  masterKey.fill(0);

  const encKey = await crypto.subtle.importKey("raw", encBits, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
  encBits.fill(0);

  const authKey = toB64(authBits);
  authBits.fill(0);
  return { encKey, authKey };
}

export async function deriveAccountKeys(masterPassword, email, iterations) {
  // Salting with the address means two people choosing the same password still
  // derive different keys, and rules out precomputed tables.
  const master = await stretch(masterPassword, normalizeEmail(email), iterations);
  return branch(master, "kalmpass/v1/client");
}

// --- the Recovery Key -------------------------------------------------------

/**
 * Crockford base32: no I, L, O or U, so a key cannot be misread off a printed
 * Emergency Kit and cannot accidentally spell anything.
 */
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** Uniform in [0, max). Rejection sampling, never a biased modulo. */
function randomInt(max) {
  const limit = Math.floor(0xffffffff / max) * max;
  const buffer = new Uint32Array(1);
  let value;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

/**
 * 25 symbols of 5 bits. 125 bits of entropy, printed in groups of five. Far
 * beyond brute force, and short enough to write on a card.
 */
export function generateRecoveryKey() {
  const symbols = Array.from({ length: 25 }, () => CROCKFORD[randomInt(32)]);
  const groups = [];
  for (let i = 0; i < 25; i += 5) groups.push(symbols.slice(i, i + 5).join(""));
  return `KP1-${groups.join("-")}`;
}

/**
 * Forgiving about transcription: case, spacing and the classic confusions (O
 * for zero, I or L for one) are all corrected before the key is used.
 */
export function normalizeRecoveryKey(input) {
  const cleaned = (input ?? "")
    .toUpperCase()
    .replace(/^KP1/, "")
    .replace(/[^0-9A-Z]/g, "")
    .replace(/O/g, "0")
    .replace(/[IL]/g, "1")
    .replace(/U/g, "V");

  if (cleaned.length !== 25) {
    throw new Error("A Recovery Key is 25 characters. Check for a missing or extra character.");
  }
  for (const symbol of cleaned) {
    if (!CROCKFORD.includes(symbol)) throw new Error("That is not a valid Recovery Key.");
  }
  return cleaned;
}

export function formatRecoveryKey(normalized) {
  return `KP1-${normalized.match(/.{1,5}/g).join("-")}`;
}

export async function deriveRecoveryKeys(recoveryKey, email) {
  const normalized = normalizeRecoveryKey(recoveryKey);
  const master = await stretch(
    normalized,
    `kalmpass-recovery:${normalizeEmail(email)}`,
    RECOVERY_KDF_ITERATIONS,
  );
  return branch(master, "kalmpass/v1/recovery");
}

// --- the vault key ----------------------------------------------------------

export async function generateVaultKey() {
  // Extractable only so it can be wrapped; the raw bytes never leave this file.
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}

export async function wrapVaultKey(encKey, vaultKey) {
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", vaultKey));
  const blob = await encryptBytes(encKey, raw);
  raw.fill(0);
  return blob;
}

export async function unwrapVaultKey(encKey, blob) {
  const raw = await decryptBytes(encKey, blob);
  const key = await crypto.subtle.importKey("raw", raw, "AES-GCM", true, ["encrypt", "decrypt"]);
  raw.fill(0);
  return key;
}

// --- AES-GCM ----------------------------------------------------------------

/**
 * A fresh 96-bit IV per encryption. AES-GCM is catastrophically weak if an IV
 * repeats under the same key, so this must never be derived or counted, only
 * drawn from the CSPRNG.
 */
async function encryptBytes(key, plaintext) {
  const iv = randomBytes(12);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return toB64(out);
}

async function decryptBytes(key, blob) {
  const raw = fromB64(blob);
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: raw.subarray(0, 12) },
    key,
    raw.subarray(12),
  );
  return new Uint8Array(plain);
}

// --- items ------------------------------------------------------------------

/**
 * Length-prefix, then pad out to a block boundary with random bytes.
 *
 * Without this, a stored blob's size would quietly leak how long a note or a
 * password is. Enough, across a whole vault, to fingerprint what is in it.
 */
function pad(bytes) {
  const total = Math.ceil((bytes.length + 4) / PAD_BLOCK) * PAD_BLOCK;
  const out = randomBytes(total);
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function unpad(bytes) {
  const length = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  if (length > bytes.length - 4) throw new Error("Item is malformed.");
  return bytes.subarray(4, 4 + length);
}

export async function encryptItem(vaultKey, item) {
  return encryptBytes(vaultKey, pad(encoder.encode(JSON.stringify(item))));
}

export async function decryptItem(vaultKey, blob) {
  return JSON.parse(decoder.decode(unpad(await decryptBytes(vaultKey, blob))));
}

// --- backups ----------------------------------------------------------------

/**
 * Exports are encrypted under their own key, derived from a passphrase chosen at
 * export time. A backup file is therefore useless to anyone who finds it and,
 * unlike the live vault, it can still be restored if the instance is lost.
 */
export async function encryptBackup(passphrase, payload) {
  const salt = randomBytes(16);
  const iterations = DEFAULT_KDF_ITERATIONS;
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations },
    material,
    256,
  );
  const key = await crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["encrypt", "decrypt"]);

  return {
    format: "kalmpass.backup",
    version: 1,
    kdf: { name: "PBKDF2-SHA256", iterations, salt: toB64(salt) },
    createdAt: new Date().toISOString(),
    data: await encryptBytes(key, pad(encoder.encode(JSON.stringify(payload)))),
  };
}

export async function decryptBackup(passphrase, backup) {
  if (backup?.format !== "kalmpass.backup") throw new Error("Not a KalmPass backup file.");
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(passphrase.normalize("NFKC")),
    "PBKDF2",
    false,
    ["deriveBits"],
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: fromB64(backup.kdf.salt),
      iterations: backup.kdf.iterations,
    },
    material,
    256,
  );
  const key = await crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["encrypt", "decrypt"]);
  return JSON.parse(decoder.decode(unpad(await decryptBytes(key, backup.data))));
}

// --- misc -------------------------------------------------------------------

/** SHA-1, uppercase hex, only ever used for the HIBP k-anonymity prefix. */
export async function sha1Hex(text) {
  const digest = await crypto.subtle.digest("SHA-1", encoder.encode(text));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}
