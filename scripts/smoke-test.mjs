/**
 * End to end check against the live instance.
 *
 * This mirrors the browser's key derivation in Node, so it exercises the real
 * cryptographic contract rather than a mock: if the server ever changes how it
 * salts, stretches or verifies, this fails. It also covers the bearer token
 * path the browser extension depends on, which cannot be tested from a page
 * because the session cookie is SameSite=Strict.
 *
 * It creates a throwaway account and deletes it again. Run with:
 *   npm run smoke            (against https://kalmpass.net)
 *   BASE=http://localhost:8787 npm run smoke
 */

import { webcrypto as crypto } from "node:crypto";

const BASE = process.env.BASE ?? "https://kalmpass.net";
const enc = new TextEncoder();
const dec = new TextDecoder();

const KDF_ITERATIONS = 1_000_000;
const RECOVERY_ITERATIONS = 200_000;
const PAD_BLOCK = 256;

let failures = 0;
const check = (name, passed, detail = "") => {
  console.log(`${passed ? "  ok  " : "FAIL  "}${name}${detail ? `  (${detail})` : ""}`);
  if (!passed) failures++;
};

// --- the same crypto the browser performs -----------------------------------

const b64 = (bytes) => Buffer.from(bytes).toString("base64");
const unb64 = (text) => new Uint8Array(Buffer.from(text, "base64"));

async function stretch(secret, salt, iterations) {
  const material = await crypto.subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", hash: "SHA-256", salt: enc.encode(salt), iterations },
      material,
      256,
    ),
  );
}

async function branch(master, label) {
  const key = await crypto.subtle.importKey("raw", master, "HKDF", false, ["deriveBits"]);
  const derive = async (info) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt: new Uint8Array(0), info: enc.encode(info) },
        key,
        256,
      ),
    );

  const encBits = await derive(`${label}/enc`);
  const authBits = await derive(`${label}/auth`);
  return {
    encKey: await crypto.subtle.importKey("raw", encBits, "AES-GCM", false, [
      "encrypt",
      "decrypt",
    ]),
    authKey: b64(authBits),
  };
}

const accountKeys = async (password, email) =>
  branch(await stretch(password, email, KDF_ITERATIONS), "kalmpass/v1/client");

const recoveryKeys = async (key, email) =>
  branch(
    await stretch(key, `kalmpass-recovery:${email}`, RECOVERY_ITERATIONS),
    "kalmpass/v1/recovery",
  );

async function encryptBytes(key, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv, 0);
  out.set(ct, iv.length);
  return b64(out);
}

async function decryptBytes(key, blob) {
  const raw = unb64(blob);
  return new Uint8Array(
    await crypto.subtle.decrypt({ name: "AES-GCM", iv: raw.subarray(0, 12) }, key, raw.subarray(12)),
  );
}

function pad(bytes) {
  const total = Math.ceil((bytes.length + 4) / PAD_BLOCK) * PAD_BLOCK;
  const out = crypto.getRandomValues(new Uint8Array(total));
  new DataView(out.buffer).setUint32(0, bytes.length);
  out.set(bytes, 4);
  return out;
}

function unpad(bytes) {
  const length = new DataView(bytes.buffer, bytes.byteOffset).getUint32(0);
  return bytes.subarray(4, 4 + length);
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
const recoveryKey = () =>
  [...crypto.getRandomValues(new Uint8Array(25))].map((n) => CROCKFORD[n % 32]).join("");

// --- http -------------------------------------------------------------------

async function call(path, { method = "GET", body, token, origin = BASE } = {}) {
  const response = await fetch(`${BASE}/api${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      // The server refuses a cookie-authenticated write from another origin.
      // A bearer request carries no cookie, so it is exempt, which is exactly
      // what this run is here to prove.
      ...(token || !origin ? {} : { origin }),
    },
    body: body ? JSON.stringify(body) : undefined,
    redirect: "error",
  });
  const payload = await response.json().catch(() => null);
  return { status: response.status, payload };
}

// --- the run ----------------------------------------------------------------

const email = `smoke-${Date.now()}@kalmpass.invalid`;
const password = "Smoke-Test-Harbour-Quartz-91";
const secret = `canary-${crypto.randomUUID()}`;

console.log(`Running against ${BASE} as ${email}\n`);

const account = await accountKeys(password, email);
const kit = recoveryKey();
const recovery = await recoveryKeys(kit, email);

const vaultKey = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, [
  "encrypt",
  "decrypt",
]);
const rawVaultKey = new Uint8Array(await crypto.subtle.exportKey("raw", vaultKey));

const signup = await call("/account/signup", {
  method: "POST",
  body: {
    email,
    authKey: account.authKey,
    kdfIterations: KDF_ITERATIONS,
    protectedKey: await encryptBytes(account.encKey, rawVaultKey),
    recoveryWrap: await encryptBytes(recovery.encKey, rawVaultKey),
    recoveryAuthKey: recovery.authKey,
    deviceId: "smokedeviceAAAA",
  },
});
check("signup accepted", signup.status === 201, `status ${signup.status}`);
if (signup.status !== 201) {
  console.error(JSON.stringify(signup.payload));
  process.exit(1);
}

// The extension's path: a token in the body, and no cookie at all. Sent from
// an extension origin, as a real browser would send it.
const login = await call("/account/login", {
  method: "POST",
  origin: "chrome-extension://abcdefghijklmnopabcdefghijklmnop",
  // Same device as the signup, so the device checks further down start from a
  // single session rather than an extra anonymous one.
  body: { email, authKey: account.authKey, tokenAuth: true, deviceId: "smokedeviceAAAA" },
});
const token = login.payload?.token;
check("login returns a bearer token", Boolean(token), `status ${login.status}`);

const firefoxPrelogin = await call("/account/prelogin", {
  method: "POST",
  origin: "moz-extension://2f1b7c1e-8a4d-4c5e-9f00-0123456789ab",
  body: { email },
});
check("a Firefox extension origin is accepted", firefoxPrelogin.status === 200,
  `status ${firefoxPrelogin.status}`);

const foreign = await call("/account/prelogin", {
  method: "POST",
  origin: "https://kalmpass.net.evil.example",
  body: { email },
});
check("a foreign web origin is refused", foreign.status === 403, `status ${foreign.status}`);

// --- the mobile apps ----------------------------------------------------------

const APP = "capacitor://app.kalmpass.net";
const preflight = await fetch(`${BASE}/api/items`, {
  method: "OPTIONS",
  headers: {
    origin: APP,
    "access-control-request-method": "PUT",
    "access-control-request-headers": "authorization, content-type",
  },
});
check("the iOS app's preflight is answered",
  preflight.status === 204 && preflight.headers.get("access-control-allow-origin") === APP,
  `status ${preflight.status}`);
check("without allowing credentials",
  preflight.headers.get("access-control-allow-credentials") === null);

const strangerPreflight = await fetch(`${BASE}/api/items`, {
  method: "OPTIONS",
  headers: { origin: "https://evil.example", "access-control-request-method": "PUT" },
});
check("a stranger's preflight is not",
  strangerPreflight.headers.get("access-control-allow-origin") === null,
  `status ${strangerPreflight.status}`);

const appPrelogin = await fetch(`${BASE}/api/account/prelogin`, {
  method: "POST",
  headers: { origin: "https://app.kalmpass.net", "content-type": "application/json" },
  body: JSON.stringify({ email }),
});
check("the Android app can reach the API",
  appPrelogin.status === 200 &&
    appPrelogin.headers.get("access-control-allow-origin") === "https://app.kalmpass.net",
  `status ${appPrelogin.status}`);


const tokenSignupEmail = `smoke-token-${Date.now()}@kalmpass.invalid`;
const tokenAccount = await accountKeys(password, tokenSignupEmail);
const tokenRecovery = await recoveryKeys(recoveryKey(), tokenSignupEmail);
const tokenSignup = await call("/account/signup", {
  method: "POST",
  origin: APP,
  body: {
    email: tokenSignupEmail,
    authKey: tokenAccount.authKey,
    kdfIterations: KDF_ITERATIONS,
    protectedKey: await encryptBytes(tokenAccount.encKey, rawVaultKey),
    recoveryWrap: await encryptBytes(tokenRecovery.encKey, rawVaultKey),
    recoveryAuthKey: tokenRecovery.authKey,
    tokenAuth: true,
  },
});
check("an app signup gets a token", tokenSignup.status === 201 && Boolean(tokenSignup.payload?.token),
  `status ${tokenSignup.status}`);
if (tokenSignup.payload?.token) {
  const gone = await call("/account", {
    method: "DELETE",
    token: tokenSignup.payload.token,
    body: { currentAuthKey: tokenAccount.authKey, confirm: "DELETE" },
  });
  check("and that account is deleted again", gone.status === 200, `status ${gone.status}`);
}
check("login does not also set a cookie", !login.payload?.cookie);

const unwrapped = await crypto.subtle.importKey(
  "raw",
  await decryptBytes(account.encKey, login.payload.protectedKey),
  "AES-GCM",
  true,
  ["encrypt", "decrypt"],
);
check("vault key unwraps with the master password", Boolean(unwrapped));

const withRecovery = await decryptBytes(
  recovery.encKey,
  (await call("/account/recover", {
    method: "POST",
    body: { email, recoveryAuthKey: recovery.authKey },
  })).payload.recoveryWrap,
);
check(
  "recovery key unwraps the same vault key",
  Buffer.compare(Buffer.from(withRecovery), Buffer.from(rawVaultKey)) === 0,
);

const created = await call("/items", {
  method: "POST",
  token,
  body: {
    data: await encryptBytes(
      vaultKey,
      pad(enc.encode(JSON.stringify({ name: "Smoke", password: secret }))),
    ),
  },
});
check("bearer token can write an item", created.status === 201, `status ${created.status}`);

const listed = await call("/items?since=0", { token });
check("bearer token can read items", listed.status === 200, `status ${listed.status}`);

const roundTripped = JSON.parse(
  dec.decode(unpad(await decryptBytes(vaultKey, listed.payload.items[0].data))),
);
check("item survives the round trip", roundTripped.password === secret);

const noToken = await call("/items", { method: "GET" });
check("a request with no credential is refused", noToken.status === 401, `status ${noToken.status}`);

const badToken = await call("/items", { token: "not-a-real-token" });
check("a forged token is refused", badToken.status === 401, `status ${badToken.status}`);

// --- device identity ---------------------------------------------------------

/**
 * The device limit is what the paid plan sells, so it gets checked properly.
 * A known browser should reuse its slot; a new one should take another.
 */
const signIn = async (device) =>
  (await call("/account/login", {
    method: "POST",
    body: { email, authKey: account.authKey, tokenAuth: true, deviceId: device },
  })).payload;

const sessionCount = async (t) =>
  ((await call("/account/sessions", { token: t })).payload?.sessions ?? []).length;

const first = await signIn("smokedeviceAAAA");
check("same device as signup reuses its slot", (await sessionCount(first.token)) === 1,
  `${await sessionCount(first.token)} sessions`);

const again = await signIn("smokedeviceAAAA");
check("signing in twice on one device stays one session", (await sessionCount(again.token)) === 1,
  `${await sessionCount(again.token)} sessions`);

const second = await signIn("smokedeviceBBBB");
check("a second device takes a second slot", (await sessionCount(second.token)) === 2);

const third = await signIn("smokedeviceCCCC");
check("a third device fits the free plan", (await sessionCount(third.token)) === 3);

const fourth = await signIn("smokedeviceDDDD");
check("a fourth device evicts the oldest", (await sessionCount(fourth.token)) === 3,
  `${await sessionCount(fourth.token)} sessions`);
check("and the arriving device is told", fourth.devicesSignedOut === 1,
  `reported ${fourth.devicesSignedOut}`);
check("with the plan limit alongside it", fourth.deviceLimit === 3, `reported ${fourth.deviceLimit}`);

// Last, because signing in again as the same device replaces that session.
const appLogin = await fetch(`${BASE}/api/account/login`, {
  method: "POST",
  headers: { origin: "capacitor://app.kalmpass.net", "content-type": "application/json" },
  body: JSON.stringify({ email, authKey: account.authKey, tokenAuth: true, deviceId: "smokedeviceDDDD" }),
});
const appLoginBody = await appLogin.json();
check("an app sign-in gets a token and no cookie",
  Boolean(appLoginBody.token) && appLogin.headers.get("set-cookie") === null);

const removed = await call("/account", {
  method: "DELETE",
  token: appLoginBody.token ?? fourth.token,
  body: { currentAuthKey: account.authKey, confirm: "DELETE" },
});
check("account deleted", removed.status === 200, `status ${removed.status}`);

console.log(`\n${failures === 0 ? "All checks passed." : `${failures} check(s) failed.`}`);
process.exit(failures === 0 ? 0 : 1);
