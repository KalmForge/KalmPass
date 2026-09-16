/**
 * The extension's background worker. It is the only place that holds keys.
 *
 * Two things shape the design:
 *
 *   1. The popup is a web page that the browser destroys the moment it closes,
 *      and the worker is torn down whenever the browser feels like it. So the
 *      unlocked state lives in chrome.storage.session, which is held in memory,
 *      never written to disk, and cleared when the browser quits.
 *
 *   2. Passwords are handed out as narrowly as possible. Filling happens here,
 *      by injecting a function into the active tab, so a password reaches the
 *      page without ever passing through the popup. The popup only receives a
 *      secret when the user has asked to copy that specific one.
 *
 * The same file runs as a service worker in Chrome and Safari and as an event
 * page in Firefox. Firefox implements the chrome.* namespace with promises, so
 * nothing here needs to know which browser it is in.
 */

import {
  DEFAULT_KDF_ITERATIONS,
  decryptItem,
  deriveAccountKeys,
  encryptItem,
  fromB64,
  normalizeEmail,
  toB64,
  unwrapVaultKey,
} from "./lib/crypto.js";
import { parseTotp, totpCode } from "./lib/totp.js";

const API = "https://kalmpass.net";
const API_HOST = "kalmpass.net";
const LOCK_ALARM = "kalmpass-lock";

/** Mirrors the web app's default. Changed from the popup. */
const DEFAULT_LOCK_MINUTES = 15;

/** Save-on-submit. See capture.js. */
const CAPTURE_ID = "kalmpass-capture";
const CAPTURE_ORIGINS = ["https://*/*"];
const OFFER_TTL = 10 * 60 * 1000;
const MAX_OFFERS = 5;

// --- settings ---------------------------------------------------------------

const DEFAULT_SETTINGS = { lockMinutes: DEFAULT_LOCK_MINUTES, capture: false, neverSave: [] };

const settings = async () => ({
  ...DEFAULT_SETTINGS,
  ...((await chrome.storage.local.get("settings")).settings ?? {}),
});

async function updateSettings(changes) {
  const next = { ...(await settings()), ...changes };
  await chrome.storage.local.set({ settings: next });
  return next;
}

// --- session state ----------------------------------------------------------

/**
 * Held in memory when the worker is alive, and rehydrated from
 * chrome.storage.session when the browser has torn it down between clicks.
 */
let state = null;

async function load() {
  if (state) return state;
  const stored = await chrome.storage.session.get("vault");
  state = stored.vault ?? null;
  return state;
}

async function save(next) {
  state = next;
  if (next) await chrome.storage.session.set({ vault: next });
  else await chrome.storage.session.remove("vault");
}

export async function lock() {
  await save(null);
  await chrome.alarms.clear(LOCK_ALARM);
  await showBadge();
}

async function touch() {
  const minutes = (await settings()).lockMinutes;
  await chrome.alarms.create(LOCK_ALARM, { delayInMinutes: minutes });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) lock();
});

/**
 * A random id for this browser profile, in local storage so it survives a
 * restart. The extension and the web app count as separate devices, which is
 * honest: they are separate sign-ins and can be revoked separately.
 */
async function deviceId() {
  const stored = await chrome.storage.local.get("deviceId");
  if (stored.deviceId) return stored.deviceId;
  const fresh = toB64(crypto.getRandomValues(new Uint8Array(16)))
    .replace(/[^A-Za-z0-9]/g, "")
    .slice(0, 22);
  await chrome.storage.local.set({ deviceId: fresh });
  return fresh;
}

// --- api --------------------------------------------------------------------

async function call(path, { method = "GET", body, token } = {}) {
  const response = await fetch(`${API}/api${path}`, {
    method,
    headers: {
      ...(body ? { "content-type": "application/json" } : {}),
      ...(token ? { authorization: `Bearer ${token}` } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
    // The cookie would not travel from this origin anyway, and asking for it
    // would only invite confusion about which credential is in play.
    credentials: "omit",
    cache: "no-store",
  });

  let payload = null;
  try {
    payload = await response.json();
  } catch {
    /* A body is not guaranteed on every status. */
  }

  if (!response.ok) {
    const error = new Error(payload?.message ?? `Request failed (${response.status})`);
    error.code = payload?.error ?? "error";
    error.status = response.status;
    throw error;
  }
  return payload;
}

// --- unlocking --------------------------------------------------------------

async function unlock({ email, password, totp, backupCode }) {
  const address = normalizeEmail(email);
  const { kdfIterations } = await call("/account/prelogin", {
    method: "POST",
    body: { email: address },
  });

  const { encKey, authKey } = await deriveAccountKeys(
    password,
    address,
    kdfIterations || DEFAULT_KDF_ITERATIONS,
  );

  const result = await call("/account/login", {
    method: "POST",
    body: {
      email: address,
      authKey,
      tokenAuth: true,
      deviceId: await deviceId(),
      ...(totp ? { totp } : {}),
      ...(backupCode ? { backupCode } : {}),
    },
  });

  const vaultKey = await unwrapVaultKey(encKey, result.protectedKey);
  const raw = new Uint8Array(await crypto.subtle.exportKey("raw", vaultKey));

  await save({
    token: result.token,
    email: result.email,
    plan: result.plan,
    // The key is kept as bytes rather than a CryptoKey because only structured
    // clonable values survive a trip through session storage.
    vaultKey: toB64(raw),
    items: await fetchItems(result.token, vaultKey),
  });
  raw.fill(0);

  await touch();
  await showBadge();
  return {
    ok: true,
    devicesSignedOut: result.devicesSignedOut ?? 0,
    deviceLimit: result.deviceLimit ?? null,
  };
}

/**
 * The whole decrypted item is kept, not just the fields the popup shows, so
 * that updating a password from here cannot quietly drop notes or history.
 */
async function fetchItems(token, vaultKey) {
  const { items } = await call("/items?since=0", { token });
  const out = [];

  for (const row of items) {
    if (row.deletedAt) continue;
    try {
      const content = await decryptItem(vaultKey, row.data);
      out.push({
        id: row.id,
        revision: row.revision,
        name: content.name ?? "",
        username: content.username ?? "",
        password: content.password ?? "",
        url: content.url ?? "",
        totp: content.totp ?? "",
        content,
      });
    } catch {
      // One unreadable row must not take the whole list down with it.
    }
  }
  return out.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
}

const vaultKeyOf = async (current) =>
  crypto.subtle.importKey("raw", fromB64(current.vaultKey), "AES-GCM", true, [
    "encrypt",
    "decrypt",
  ]);

async function reload(current) {
  const next = { ...current, items: await fetchItems(current.token, await vaultKeyOf(current)) };
  await save(next);
  return next;
}

// --- matching ---------------------------------------------------------------

export function hostOf(url) {
  if (!url) return "";
  try {
    return new URL(url.includes("://") ? url : `https://${url}`).hostname.replace(/^www\./, "");
  } catch {
    return "";
  }
}

/**
 * Matches an item against the page you are on.
 *
 * Exact host first, then a registrable-suffix match so that an entry saved for
 * example.com still offers itself on accounts.example.com. It deliberately does
 * not match the other way around, and never matches on a bare substring, which
 * is how autofill gets tricked into offering a password to evil-example.com.
 */
export function matches(itemHost, pageHost) {
  if (!itemHost || !pageHost) return false;
  if (itemHost === pageHost) return true;
  return pageHost.endsWith(`.${itemHost}`);
}

// --- filling ----------------------------------------------------------------

/**
 * Runs inside the page. Everything it needs is passed in, because it does not
 * share a scope with the worker.
 */
function fillForm(username, password) {
  const visible = (node) => {
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && getComputedStyle(node).visibility !== "hidden";
  };

  const passwordField = [...document.querySelectorAll('input[type="password"]')].find(visible);

  // The username is whichever candidate sits closest above the password box,
  // which is far more reliable across real sites than guessing at field names.
  const candidates = [
    ...document.querySelectorAll(
      'input[type="text"], input[type="email"], input[type="tel"], input:not([type])',
    ),
  ].filter(visible);

  let usernameField = null;
  if (passwordField) {
    const limit = passwordField.getBoundingClientRect().top;
    const above = candidates.filter((n) => n.getBoundingClientRect().top <= limit);
    usernameField = above[above.length - 1] ?? candidates[0] ?? null;
  } else {
    usernameField = candidates[0] ?? null;
  }

  const set = (field, value) => {
    if (!field || !value) return false;
    const setter = Object.getOwnPropertyDescriptor(
      window.HTMLInputElement.prototype,
      "value",
    )?.set;
    // Frameworks track their own state, so assigning through the native setter
    // and dispatching real events is what makes React and friends notice.
    setter ? setter.call(field, value) : (field.value = value);
    field.dispatchEvent(new Event("input", { bubbles: true }));
    field.dispatchEvent(new Event("change", { bubbles: true }));
    return true;
  };

  const filledUser = set(usernameField, username);
  const filledPass = set(passwordField, password);
  if (filledPass) passwordField.focus();

  return { username: filledUser, password: filledPass };
}

const refuse = (code, message) => Object.assign(new Error(message), { code });

/** https, or plain http on this machine only. */
function pageUrlOf(url) {
  let page;
  try {
    page = new URL(url ?? "");
  } catch {
    return null;
  }
  const local = page.hostname === "localhost" || page.hostname === "127.0.0.1";
  return { page, secure: page.protocol === "https:" || (page.protocol === "http:" && local) };
}

/**
 * Refuses to fill without a second click when the page is not the site the
 * login was saved for, or when the page is not encrypted. The tab is read
 * here, at the moment of filling, so a page that navigated after the popup
 * opened is caught too.
 */
function assertSafeToFill(item, tab) {
  const parsed = pageUrlOf(tab.url);
  if (!parsed || (parsed.page.protocol !== "https:" && parsed.page.protocol !== "http:")) {
    throw new Error("This page cannot be filled.");
  }
  if (!parsed.secure) {
    throw refuse(
      "insecure_page",
      `${parsed.page.hostname} is not using an encrypted connection, so anything typed there can be read in transit.`,
    );
  }

  const saved = hostOf(item.url);
  const here = hostOf(parsed.page.href);
  if (saved && !matches(saved, here)) {
    throw refuse("host_mismatch", `This login is saved for ${saved}, but this page is ${here}.`);
  }
}

async function fill(id, { anyway = false } = {}) {
  const current = await load();
  if (!current) throw new Error("Vault is locked.");

  const item = current.items.find((row) => row.id === id);
  if (!item) throw new Error("That item is no longer in your vault.");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab.");
  if (!anyway) assertSafeToFill(item, tab);

  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillForm,
    args: [item.username, item.password],
    // The isolated world, not the page's own. Page scripts cannot reach into
    // it to patch the functions this relies on, and it works the same in
    // Chrome, Firefox and Safari.
  });

  await touch();
  if (!result?.result?.password) throw new Error("No password field found on this page.");
  return { ok: true };
}

// --- save on submit ---------------------------------------------------------

/**
 * Offers are logins somebody has just typed into a page, waiting for them to
 * say whether to keep them. They live in session storage, so they are held in
 * memory only, and they expire after a few minutes whether or not anybody
 * looks at them.
 */
async function loadOffers() {
  const { offers = [] } = await chrome.storage.session.get("offers");
  const fresh = offers.filter((offer) => Date.now() - offer.at < OFFER_TTL);
  if (fresh.length !== offers.length) await chrome.storage.session.set({ offers: fresh });
  return fresh;
}

async function storeOffers(offers) {
  await chrome.storage.session.set({ offers });
  await showBadge();
}

async function dropOffer(id) {
  await storeOffers((await loadOffers()).filter((offer) => offer.id !== id));
}

/** A plus on the icon while there is something to save. Nothing otherwise. */
async function showBadge() {
  const waiting = (await loadOffers()).length > 0;
  await chrome.action.setBadgeBackgroundColor({ color: "#1b5fc4" });
  await chrome.action.setBadgeText({ text: waiting ? "+" : "" });
}

/**
 * Decides what an offer would do against the vault as it stands: nothing, if
 * the login is already saved; update, if the same account on the same site has
 * a different password; otherwise save a new item.
 */
function classify(offer, items) {
  const onSite = items.filter((item) => matches(hostOf(item.url), offer.host));
  const user = offer.username.trim().toLowerCase();
  const sameUser = user
    ? onSite.filter((item) => item.username.trim().toLowerCase() === user)
    : onSite.length === 1
      ? onSite
      : [];

  if (sameUser.some((item) => item.password === offer.password)) return { kind: "known" };
  if (sameUser.length === 1) {
    return { kind: "update", itemId: sameUser[0].id, itemName: sameUser[0].name };
  }
  return { kind: "save" };
}

async function captured(message, sender) {
  const current = await settings();
  if (!current.capture) return { ok: false };

  const parsed = pageUrlOf(sender.url);
  if (!parsed?.secure) return { ok: false };

  const host = hostOf(parsed.page.href);
  // Never offer to save the master password into the vault it opens.
  if (!host || matches(API_HOST, host)) return { ok: false };
  if (current.neverSave.includes(host)) return { ok: false };

  const password = typeof message.password === "string" ? message.password : "";
  const username = typeof message.username === "string" ? message.username.slice(0, 256) : "";
  if (!password || password.length > 1024) return { ok: false };

  const vault = await load();
  if (vault && classify({ host, username, password }, vault.items).kind === "known") {
    return { ok: true };
  }

  const others = (await loadOffers()).filter(
    (offer) => !(offer.host === host && offer.username === username),
  );
  const id = toB64(crypto.getRandomValues(new Uint8Array(12))).replace(/[^A-Za-z0-9]/g, "");
  await storeOffers(
    [
      { id, host, origin: parsed.page.origin, username, password, at: Date.now() },
      ...others,
    ].slice(0, MAX_OFFERS),
  );
  return { ok: true };
}

/** The newest offer, described without its password. */
async function nextOffer() {
  const vault = await load();
  if (!vault) return { offer: null, waiting: (await loadOffers()).length };

  for (const offer of await loadOffers()) {
    const verdict = classify(offer, vault.items);
    if (verdict.kind === "known") {
      await dropOffer(offer.id);
      continue;
    }
    return {
      offer: {
        id: offer.id,
        host: offer.host,
        username: offer.username,
        kind: verdict.kind,
        itemName: verdict.itemName ?? null,
      },
    };
  }
  return { offer: null };
}

async function acceptOffer(id) {
  let vault = await load();
  if (!vault) throw new Error("Vault is locked.");
  const offer = (await loadOffers()).find((row) => row.id === id);
  if (!offer) throw new Error("That login is no longer waiting to be saved.");

  // Work from the vault as it is now, so an update carries the latest revision.
  vault = await reload(vault);
  const vaultKey = await vaultKeyOf(vault);
  const verdict = classify(offer, vault.items);
  const now = Date.now();

  if (verdict.kind === "update") {
    const item = vault.items.find((row) => row.id === verdict.itemId);
    const content = {
      ...item.content,
      password: offer.password,
      passwordUpdatedAt: now,
      // The same short history the web app keeps, so a mistaken update can
      // be undone from there.
      history: [
        ...(item.password ? [{ password: item.password, changedAt: now }] : []),
        ...(item.content.history ?? []),
      ].slice(0, 5),
    };
    await call(`/items/${item.id}`, {
      method: "PUT",
      token: vault.token,
      body: { data: await encryptItem(vaultKey, content), revision: item.revision },
    });
  } else if (verdict.kind === "save") {
    const content = {
      name: offer.host,
      username: offer.username,
      password: offer.password,
      url: offer.origin,
      notes: "",
      totp: "",
      favorite: false,
      folder: "",
      passwordUpdatedAt: now,
      history: [],
    };
    await call("/items", {
      method: "POST",
      token: vault.token,
      body: { data: await encryptItem(vaultKey, content) },
    });
  }

  await dropOffer(id);
  await reload(vault);
  await touch();
  return { ok: true, kind: verdict.kind };
}

/**
 * The content script is registered only while the setting is on and the
 * browser has granted access to sites. Checked on every start, because the
 * user can withdraw the permission from the browser's own settings.
 */
async function syncCapture() {
  const wanted = (await settings()).capture;
  const granted = await chrome.permissions.contains({ origins: CAPTURE_ORIGINS });
  const registered = await chrome.scripting.getRegisteredContentScripts({ ids: [CAPTURE_ID] });

  if (wanted && granted && registered.length === 0) {
    await chrome.scripting.registerContentScripts([
      {
        id: CAPTURE_ID,
        matches: CAPTURE_ORIGINS,
        excludeMatches: [`https://${API_HOST}/*`],
        js: ["capture.js"],
        runAt: "document_idle",
      },
    ]);
  } else if (!(wanted && granted) && registered.length > 0) {
    await chrome.scripting.unregisterContentScripts({ ids: [CAPTURE_ID] });
  }
  return wanted && granted;
}

chrome.runtime.onStartup.addListener(() => syncCapture().catch(() => {}));
chrome.runtime.onInstalled.addListener(() => syncCapture().catch(() => {}));
chrome.permissions.onRemoved.addListener(() => syncCapture().catch(() => {}));

// --- messages ---------------------------------------------------------------

/** Messages the extension's own pages may send. */
const handlers = {
  async state() {
    const current = await load();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    const prefs = await settings();
    return {
      locked: !current,
      email: current?.email ?? null,
      plan: current?.plan ?? null,
      host: hostOf(tab?.url ?? ""),
      count: current?.items.length ?? 0,
      lockMinutes: prefs.lockMinutes,
      capture: prefs.capture && (await chrome.permissions.contains({ origins: CAPTURE_ORIGINS })),
    };
  },

  unlock: (message) => unlock(message),

  async lock() {
    await lock();
    return { ok: true };
  },

  async signOut() {
    const current = await load();
    if (current) {
      try {
        await call("/account/logout", { method: "POST", token: current.token });
      } catch {
        // The local keys go either way; a failed call must not strand them.
      }
    }
    await lock();
    return { ok: true };
  },

  /** Summaries only. No secret leaves the worker until it is asked for. */
  async list({ query, host }) {
    const current = await load();
    if (!current) return { locked: true, items: [] };
    await touch();

    const needle = (query ?? "").trim().toLowerCase();
    const items = current.items
      .map((item) => ({
        id: item.id,
        name: item.name || hostOf(item.url) || "Untitled",
        username: item.username,
        host: hostOf(item.url),
        hasTotp: Boolean(item.totp),
        onThisSite: matches(hostOf(item.url), host),
      }))
      .filter((item) =>
        needle
          ? [item.name, item.username, item.host].some((field) =>
              field.toLowerCase().includes(needle),
            )
          : true,
      );

    // Whatever belongs to the page you are looking at goes to the top.
    items.sort((a, b) => Number(b.onThisSite) - Number(a.onThisSite));
    return { locked: false, items };
  },

  async secret({ id, field }) {
    const current = await load();
    if (!current) throw new Error("Vault is locked.");
    const item = current.items.find((row) => row.id === id);
    if (!item) throw new Error("That item is no longer in your vault.");
    await touch();

    if (field === "totp") {
      const config = parseTotp(item.totp);
      if (!config) throw new Error("No authenticator key on this item.");
      return { value: await totpCode(config) };
    }
    return { value: field === "username" ? item.username : item.password };
  },

  fill: ({ id, anyway }) => fill(id, { anyway: anyway === true }),

  async refresh() {
    const current = await load();
    if (!current) throw new Error("Vault is locked.");
    const next = await reload(current);
    await touch();
    return { ok: true, count: next.items.length };
  },

  async setLockMinutes({ minutes }) {
    const lockMinutes = Math.max(1, Math.min(240, Number(minutes) || DEFAULT_LOCK_MINUTES));
    await updateSettings({ lockMinutes });
    await touch();
    return { ok: true, lockMinutes };
  },

  /** The popup asks the browser for the permission first, then calls this. */
  async setCapture({ on }) {
    await updateSettings({ capture: on === true });
    if (on !== true) await storeOffers([]);
    return { ok: true, capture: await syncCapture() };
  },

  offer: () => nextOffer(),

  acceptOffer: ({ id }) => acceptOffer(id),

  async dismissOffer({ id, never }) {
    const offer = (await loadOffers()).find((row) => row.id === id);
    if (offer && never === true) {
      const prefs = await settings();
      await updateSettings({ neverSave: [...new Set([...prefs.neverSave, offer.host])] });
    }
    await dropOffer(id);
    return { ok: true };
  },
};

/**
 * Messages a page may cause, through the content script. Deliberately one
 * entry long: whatever a hostile page does to the script running inside it,
 * the most it can achieve is to suggest a login for its own site.
 */
const pageHandlers = {
  captured,
};

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (sender.id !== chrome.runtime.id) return false;

  const fromExtension = (sender.url ?? "").startsWith(chrome.runtime.getURL(""));
  const fromTopFrame = Boolean(sender.tab) && sender.frameId === 0;
  const table = fromExtension ? handlers : fromTopFrame ? pageHandlers : {};

  const handler = Object.hasOwn(table, message?.type) ? table[message.type] : null;
  if (!handler) {
    sendResponse({ error: "unknown_message" });
    return false;
  }

  handler(message, sender)
    .then((result) => sendResponse(result))
    .catch((error) => sendResponse({ error: error.code ?? "error", message: error.message }));

  // Keeps the message channel open for the async reply.
  return true;
});
