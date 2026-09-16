/**
 * Runs the extension's real background worker in Node, against the live
 * server, with the browser APIs replaced by small in-memory fakes.
 *
 * What this proves is the part that matters most and is hardest to click
 * through by hand: that the extension signs in from an extension origin, that
 * a captured login is saved into the vault encrypted so the web app can read
 * it, that a changed password updates the right item without losing its notes,
 * and that a page cannot reach any handler beyond suggesting a login.
 *
 * It creates a throwaway account and deletes it again. Run with:
 *   npm run ext:test
 */

import {
  decryptItem,
  deriveAccountKeys,
  deriveRecoveryKeys,
  encryptItem,
  generateRecoveryKey,
  generateVaultKey,
  wrapVaultKey,
} from "../extension/lib/crypto.js";

const BASE = "https://kalmpass.net";
const EXTENSION_ORIGIN = "chrome-extension://abcdefghijklmnopabcdefghijklmnop";

let failures = 0;
const check = (name, passed, detail = "") => {
  console.log(`${passed ? "  ok  " : "FAIL  "}${name}${detail ? `  (${detail})` : ""}`);
  if (!passed) failures++;
};

// --- the browser, faked -----------------------------------------------------

const listeners = {};
const event = (name) => ({ addListener: (fn) => (listeners[name] = fn) });

function storageArea() {
  const data = {};
  return {
    data,
    async get(key) {
      return key in data ? { [key]: structuredClone(data[key]) } : {};
    },
    async set(values) {
      Object.assign(data, structuredClone(values));
    },
    async remove(key) {
      delete data[key];
    },
  };
}

const browser = {
  badge: "",
  granted: false,
  registered: [],
  filled: null,
  tab: { id: 7, url: "https://accounts.example.com/login" },
};

globalThis.chrome = {
  storage: { session: storageArea(), local: storageArea() },
  alarms: { onAlarm: event("alarm"), create: async () => {}, clear: async () => {} },
  action: {
    setBadgeText: async ({ text }) => void (browser.badge = text),
    setBadgeBackgroundColor: async () => {},
  },
  runtime: {
    id: "kalmpass-test",
    getURL: (path) => `chrome-extension://kalmpass-test/${path}`,
    onMessage: event("message"),
    onStartup: event("startup"),
    onInstalled: event("installed"),
  },
  permissions: { contains: async () => browser.granted, onRemoved: event("removed") },
  scripting: {
    getRegisteredContentScripts: async ({ ids }) =>
      browser.registered.filter((script) => ids.includes(script.id)),
    registerContentScripts: async (scripts) => void browser.registered.push(...scripts),
    unregisterContentScripts: async ({ ids }) => {
      browser.registered = browser.registered.filter((script) => !ids.includes(script.id));
    },
    executeScript: async ({ args }) => {
      browser.filled = args;
      return [{ result: { username: true, password: true } }];
    },
  },
  tabs: { query: async () => [browser.tab] },
};

// A real browser labels every request from the extension with its origin.
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init = {}) =>
  realFetch(url, { ...init, headers: { ...init.headers, origin: EXTENSION_ORIGIN } });

await import("../extension/background.js");

const POPUP = { id: "kalmpass-test", url: "chrome-extension://kalmpass-test/popup.html" };
const pageSender = (url, frameId = 0) => ({ id: "kalmpass-test", url, tab: { id: 7 }, frameId });

const send = (message, sender = POPUP) =>
  new Promise((resolve) => {
    // A listener that returns false without answering has ignored the message.
    let answered = false;
    const keepOpen = listeners.message(message, sender, (reply) => {
      answered = true;
      resolve(reply);
    });
    if (!keepOpen && !answered) resolve(undefined);
  });

// --- an account to test with --------------------------------------------------

const email = `ext-${Date.now()}@kalmpass.invalid`;
const password = "Extension-Test-Lantern-Opal-47";
console.log(`Running against ${BASE} as ${email}\n`);

const vaultKey = await generateVaultKey();
const account = await deriveAccountKeys(password, email, 1_000_000);
const recovery = await deriveRecoveryKeys(generateRecoveryKey(), email);

const signup = await realFetch(`${BASE}/api/account/signup`, {
  method: "POST",
  headers: { "content-type": "application/json", origin: BASE },
  body: JSON.stringify({
    email,
    authKey: account.authKey,
    kdfIterations: 1_000_000,
    protectedKey: await wrapVaultKey(account.encKey, vaultKey),
    recoveryWrap: await wrapVaultKey(recovery.encKey, vaultKey),
    recoveryAuthKey: recovery.authKey,
  }),
});
check("signup accepted", signup.status === 201, `status ${signup.status}`);
if (signup.status !== 201) process.exit(1);

// One item made the way the web app makes it, with notes that must survive.
let token = null;
try {
  const unlocked = await send({ type: "unlock", email, password });
  check("the extension unlocks", unlocked.ok === true, unlocked.message ?? "");
  token = (await chrome.storage.session.get("vault")).vault?.token;

  const seed = await realFetch(`${BASE}/api/items`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
    body: JSON.stringify({
      data: await encryptItem(vaultKey, {
        name: "Example",
        username: "sam@example.com",
        password: "old-password-1",
        url: "https://example.com",
        notes: "keep these notes",
        history: [],
      }),
    }),
  });
  check("a web-style item is created", seed.status === 201, `status ${seed.status}`);
  await send({ type: "refresh" });

  // --- filling ----------------------------------------------------------------

  const { items } = await send({ type: "list", query: "", host: "accounts.example.com" });
  check("the item matches a subdomain of its site", items[0]?.onThisSite === true);

  browser.tab = { id: 7, url: "https://examp1e.com/login" };
  const wrongSite = await send({ type: "fill", id: items[0].id });
  check("filling on another site asks first", wrongSite.error === "host_mismatch");
  check("and fills nothing", browser.filled === null);

  browser.tab = { id: 7, url: "http://example.com/login" };
  const plain = await send({ type: "fill", id: items[0].id });
  check("filling an unencrypted page asks first", plain.error === "insecure_page");

  const anyway = await send({ type: "fill", id: items[0].id, anyway: true });
  check("fill anyway goes ahead", anyway.ok === true && browser.filled?.[1] === "old-password-1");

  browser.tab = { id: 7, url: "https://www.example.com/login" };
  browser.filled = null;
  const right = await send({ type: "fill", id: items[0].id });
  check("filling on the right site just works", right.ok === true && browser.filled !== null);

  // --- save on submit ---------------------------------------------------------

  const early = await send(
    { type: "captured", username: "sam@example.com", password: "new-password-2" },
    pageSender("https://example.com/login"),
  );
  check("nothing is captured while the setting is off", early.ok === false);

  browser.granted = true;
  const enabled = await send({ type: "setCapture", on: true });
  check("turning it on registers the content script", enabled.capture === true &&
    browser.registered.length === 1);
  check("which never runs on kalmpass.net",
    browser.registered[0]?.excludeMatches?.includes("https://kalmpass.net/*"));

  const own = await send(
    { type: "captured", username: email, password },
    pageSender("https://kalmpass.net/app/"),
  );
  check("the master password is never offered for saving", own.ok === false);

  const same = await send(
    { type: "captured", username: "sam@example.com", password: "old-password-1" },
    pageSender("https://example.com/login"),
  );
  const nothing = await send({ type: "offer" });
  check("a login already saved is not offered", same.ok === true && nothing.offer === null);
  check("and the icon stays clear", browser.badge === "");

  await send(
    { type: "captured", username: "sam@example.com", password: "new-password-2" },
    pageSender("https://example.com/login"),
  );
  check("a changed password lights the icon", browser.badge === "+");
  const change = await send({ type: "offer" });
  check("and is offered as an update", change.offer?.kind === "update", change.offer?.kind);
  check("the offer carries no password", !JSON.stringify(change).includes("new-password-2"));

  const updated = await send({ type: "acceptOffer", id: change.offer.id });
  check("accepting it updates the item", updated.kind === "update", updated.message ?? "");
  check("and clears the icon", browser.badge === "");

  await send(
    { type: "captured", username: "alex", password: "brand-new-3" },
    pageSender("https://shop.test.dev/signin"),
  );
  const fresh = await send({ type: "offer" });
  check("a new site is offered as a save", fresh.offer?.kind === "save");
  const saved = await send({ type: "acceptOffer", id: fresh.offer.id });
  check("accepting it saves the item", saved.kind === "save", saved.message ?? "");

  await send(
    { type: "captured", username: "pat", password: "whatever-4" },
    pageSender("https://nosy.test.dev/"),
  );
  const nosy = await send({ type: "offer" });
  await send({ type: "dismissOffer", id: nosy.offer.id, never: true });
  await send(
    { type: "captured", username: "pat", password: "whatever-5" },
    pageSender("https://nosy.test.dev/"),
  );
  check("never for this site is remembered", (await send({ type: "offer" })).offer === null);

  const insecure = await send(
    { type: "captured", username: "a", password: "b" },
    pageSender("http://plain.test.dev/"),
  );
  check("nothing is captured from an unencrypted page", insecure.ok === false);

  // --- what the server now holds, read the way the web app reads it ---------

  const listed = await realFetch(`${BASE}/api/items?since=0`, {
    headers: { authorization: `Bearer ${token}` },
  }).then((r) => r.json());
  const contents = await Promise.all(listed.items.map((row) => decryptItem(vaultKey, row.data)));
  const example = contents.find((item) => item.name === "Example");
  const shop = contents.find((item) => item.url === "https://shop.test.dev");

  check("the web app sees the new password", example?.password === "new-password-2");
  check("the notes survived the update", example?.notes === "keep these notes");
  check("the old password went into history", example?.history?.[0]?.password === "old-password-1");
  check("the saved login is readable by the web app",
    shop?.username === "alex" && shop?.password === "brand-new-3");
  check("the server holds no plaintext",
    !JSON.stringify(listed).includes("new-password-2") && !JSON.stringify(listed).includes("alex"));

  // --- what a page cannot do --------------------------------------------------

  const stolen = await send({ type: "secret", id: items[0].id, field: "password" },
    pageSender("https://example.com/"));
  check("a page cannot ask for a password", stolen.error === "unknown_message");
  const listing = await send({ type: "list", query: "" }, pageSender("https://example.com/"));
  check("a page cannot list the vault", listing.error === "unknown_message");
  const framed = await send({ type: "captured", username: "x", password: "y" },
    pageSender("https://example.com/", 3));
  check("a frame inside a page cannot suggest logins", framed.error === "unknown_message");
  const foreign = await send({ type: "state" }, { ...POPUP, id: "someone-else" });
  check("another extension is ignored", foreign === undefined || foreign.error !== undefined);

  const off = await send({ type: "setCapture", on: false });
  check("turning it off removes the content script",
    off.capture === false && browser.registered.length === 0);
} finally {
  if (token) {
    const removed = await realFetch(`${BASE}/api/account`, {
      method: "DELETE",
      headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
      body: JSON.stringify({ currentAuthKey: account.authKey, confirm: "DELETE" }),
    });
    check("account deleted", removed.status === 200, `status ${removed.status}`);
  }
}

console.log(`\n${failures === 0 ? "All checks passed." : `${failures} check(s) failed.`}`);
process.exit(failures === 0 ? 0 : 1);
