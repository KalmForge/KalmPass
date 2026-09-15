/**
 * The extension's service worker. It is the only place that holds keys.
 *
 * Two things shape the design:
 *
 *   1. The popup is a web page that Chrome destroys the moment it closes, and
 *      the service worker is torn down whenever Chrome feels like it. So the
 *      unlocked state lives in chrome.storage.session, which is held in memory,
 *      never written to disk, and cleared when the browser quits.
 *
 *   2. Passwords are handed out as narrowly as possible. Filling happens here,
 *      by injecting a function into the active tab, so a password reaches the
 *      page without ever passing through the popup. The popup only receives a
 *      secret when the user has asked to copy or reveal that specific one.
 */

import {
  DEFAULT_KDF_ITERATIONS,
  decryptItem,
  deriveAccountKeys,
  fromB64,
  normalizeEmail,
  toB64,
  unwrapVaultKey,
} from "./lib/crypto.js";
import { parseTotp, totpCode } from "./lib/totp.js";

const API = "https://kalmpass.net";
const LOCK_ALARM = "kalmpass-lock";

/** Mirrors the web app's default. Changed from the popup's settings. */
const DEFAULT_LOCK_MINUTES = 15;

// --- session state ----------------------------------------------------------

/**
 * Held in memory when the worker is alive, and rehydrated from
 * chrome.storage.session when Chrome has torn it down between clicks.
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
  await chrome.action.setBadgeText({ text: "" });
}

async function touch() {
  const minutes = (await settings()).lockMinutes;
  await chrome.alarms.create(LOCK_ALARM, { delayInMinutes: minutes });
}

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === LOCK_ALARM) lock();
});

const settings = async () => ({
  lockMinutes: DEFAULT_LOCK_MINUTES,
  ...((await chrome.storage.local.get("settings")).settings ?? {}),
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
  await chrome.action.setBadgeText({ text: "" });
  return {
    ok: true,
    devicesSignedOut: result.devicesSignedOut ?? 0,
    deviceLimit: result.deviceLimit ?? null,
  };
}

async function fetchItems(token, vaultKey) {
  const { items } = await call("/items?since=0", { token });
  const out = [];

  for (const row of items) {
    if (row.deletedAt) continue;
    try {
      const content = await decryptItem(vaultKey, row.data);
      out.push({
        id: row.id,
        name: content.name ?? "",
        username: content.username ?? "",
        password: content.password ?? "",
        url: content.url ?? "",
        totp: content.totp ?? "",
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
 * share a scope with the service worker.
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

async function fill(id) {
  const current = await load();
  if (!current) throw new Error("Vault is locked.");

  const item = current.items.find((row) => row.id === id);
  if (!item) throw new Error("That item is no longer in your vault.");

  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) throw new Error("No active tab.");

  const [result] = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: fillForm,
    args: [item.username, item.password],
    world: "MAIN",
  });

  await touch();
  if (!result?.result?.password) throw new Error("No password field found on this page.");
  return { ok: true };
}

// --- messages ---------------------------------------------------------------

const handlers = {
  async state() {
    const current = await load();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    return {
      locked: !current,
      email: current?.email ?? null,
      plan: current?.plan ?? null,
      host: hostOf(tab?.url ?? ""),
      count: current?.items.length ?? 0,
      lockMinutes: (await settings()).lockMinutes,
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

  fill: ({ id }) => fill(id),

  async refresh() {
    const current = await load();
    if (!current) throw new Error("Vault is locked.");
    const vaultKey = await vaultKeyOf(current);
    await save({ ...current, items: await fetchItems(current.token, vaultKey) });
    await touch();
    return { ok: true, count: state.items.length };
  },

  async setLockMinutes({ minutes }) {
    const lockMinutes = Math.max(1, Math.min(240, Number(minutes) || DEFAULT_LOCK_MINUTES));
    await chrome.storage.local.set({ settings: { lockMinutes } });
    await touch();
    return { ok: true, lockMinutes };
  },
};

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  const handler = handlers[message?.type];
  if (!handler) {
    sendResponse({ error: "unknown_message" });
    return false;
  }

  handler(message)
    .then((result) => sendResponse(result))
    .catch((error) => sendResponse({ error: error.code ?? "error", message: error.message }));

  // Keeps the message channel open for the async reply.
  return true;
});
