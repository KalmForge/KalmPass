/**
 * Vault state.
 *
 * Decrypted items live here, in memory, for exactly as long as the vault is
 * unlocked. Nothing is written to localStorage, sessionStorage or IndexedDB, so
 * an unlocked vault leaves no trace on disk and closing the tab really is the
 * end of it.
 */

import { ApiError, api } from "./api.js";
import {
  DEFAULT_KDF_ITERATIONS,
  decryptBackup,
  decryptItem,
  deriveAccountKeys,
  deriveRecoveryKeys,
  encryptBackup,
  encryptItem,
  generateRecoveryKey,
  derivePasskeyKeys,
  generateVaultKey,
  normalizeEmail,
  randomBytes,
  toB64,
  unwrapVaultKey,
  wrapVaultKey,
} from "./crypto.js";

const CONTENT_FIELDS = [
  "name",
  "username",
  "password",
  "url",
  "notes",
  "totp",
  "favorite",
  "folder",
  "passwordUpdatedAt",
  "history",
];

/**
 * A random id for this browser, kept so that signing in again here replaces
 * this machine session rather than counting as another device.
 *
 * Not a secret and not a credential: it identifies the browser, never the
 * person, and it is useless without a master password. It joins the two
 * preference values as the only things KalmPass writes to disk. If storage is
 * unavailable we do without, and every sign-in counts separately as before.
 */
function deviceId() {
  try {
    const existing = localStorage.getItem("kalmpass.device");
    if (existing) return existing;
    const fresh = toB64(randomBytes(16)).replace(/[^A-Za-z0-9]/g, "").slice(0, 22);
    localStorage.setItem("kalmpass.device", fresh);
    return fresh;
  } catch {
    return null;
  }
}

const listeners = new Set();

export const vault = {
  locked: true,
  email: null,
  kdfIterations: DEFAULT_KDF_ITERATIONS,
  totpEnabled: false,
  emailVerified: false,
  hasRecoveryKey: false,
  recoveryCreatedAt: null,
  plan: "free",
  planStatus: null,
  planPeriodEnd: null,
  itemCount: 0,
  items: [],
};

/**
 * Key material, deliberately not a property of the object handed to the UI.
 *
 * Only the vault key is held. The key derived from the master password exists
 * just long enough to unwrap it, and the operations that need it again, changing
 * the password or the address, ask for the password and derive it afresh. There
 * is no reason to keep a key around that nothing reads.
 */
const keys = { vault: null };

/** Held only between the two halves of a Recovery Key flow. */
let recoveryState = null;

export function onChange(listener) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

const emit = () => {
  for (const listener of listeners) listener(vault);
};

function adopt(account) {
  Object.assign(vault, {
    locked: false,
    email: account.email,
    kdfIterations: account.kdfIterations,
    totpEnabled: Boolean(account.totpEnabled),
    emailVerified: Boolean(account.emailVerified),
    hasRecoveryKey: account.hasRecoveryKey ?? true,
    recoveryCreatedAt: account.recoveryCreatedAt ?? null,
    plan: account.plan ?? "free",
    planStatus: account.planStatus ?? null,
    planPeriodEnd: account.planPeriodEnd ?? null,
    items: [],
  });
}

// --- signing up -------------------------------------------------------------

/**
 * Creates the account and returns the Recovery Key, which is shown once and
 * never again.
 *
 * The vault key is wrapped twice here, once under the master password, once
 * under the Recovery Key, and both wrapped copies go to the server. Neither
 * unwrapping secret does, which is why a forgotten password is recoverable by
 * the account holder and by nobody else.
 */
export async function signup(email, masterPassword, setupCode) {
  const iterations = DEFAULT_KDF_ITERATIONS;
  const address = normalizeEmail(email);

  const vaultKey = await generateVaultKey();
  const recoveryKey = generateRecoveryKey();

  const [account, recovery] = await Promise.all([
    deriveAccountKeys(masterPassword, address, iterations),
    deriveRecoveryKeys(recoveryKey, address),
  ]);

  const result = await api.signup({
    email: address,
    authKey: account.authKey,
    kdfIterations: iterations,
    protectedKey: await wrapVaultKey(account.encKey, vaultKey),
    recoveryWrap: await wrapVaultKey(recovery.encKey, vaultKey),
    recoveryAuthKey: recovery.authKey,
    deviceId: deviceId(),
    ...(setupCode ? { setupCode } : {}),
  });

  keys.vault = vaultKey;
  adopt({ ...result, hasRecoveryKey: true });
  emit();

  return recoveryKey;
}

// --- signing in -------------------------------------------------------------

/**
 * Throws with `code === "totp_required"` when a second factor is set, the
 * caller collects the code and calls again with it. That ordering is
 * deliberate: the second factor is only mentioned once the master password has
 * already been accepted.
 */
export async function unlock(email, masterPassword, { totp, backupCode } = {}) {
  const address = normalizeEmail(email);
  const { kdfIterations } = await api.prelogin(address);
  const { encKey, authKey } = await deriveAccountKeys(masterPassword, address, kdfIterations);

  const result = await api.login({
    email: address,
    authKey,
    deviceId: deviceId(),
    ...(totp ? { totp } : {}),
    ...(backupCode ? { backupCode } : {}),
  });

  keys.vault = await unwrapVaultKey(encKey, result.protectedKey);
  adopt(result);
  await load();

  // Reported so the arriving device can say what happened. Being signed out
  // elsewhere with no explanation is the kind of thing people assume is a bug.
  return {
    devicesSignedOut: result.devicesSignedOut ?? 0,
    deviceLimit: result.deviceLimit ?? null,
  };
}

/** Re-opens an existing server session after a reload, given the password again. */
export async function resume(masterPassword) {
  const account = await api.me();
  const { encKey } = await deriveAccountKeys(
    masterPassword,
    account.email,
    account.kdfIterations,
  );
  keys.vault = await unwrapVaultKey(encKey, account.protectedKey);
  adopt(account);
  await load();
}

export const hasServerSession = async () => {
  try {
    return await api.me();
  } catch {
    return null;
  }
};

/** Drops every key and every plaintext item. The server session is untouched. */
export function lock() {
  keys.vault = null;
  recoveryState = null;
  Object.assign(vault, { locked: true, items: [] });
  emit();
}

export async function signOut() {
  try {
    await api.logout();
  } finally {
    lock();
    Object.assign(vault, { email: null, totpEnabled: false });
    emit();
  }
}

// --- passkeys ---------------------------------------------------------------

/**
 * Registers a passkey against the open vault.
 *
 * The secret the authenticator produces is split like the Recovery Key is, and
 * the vault key is wrapped with the encryption half. Nothing that could open the
 * vault leaves this function.
 */
export async function addPasskey(label) {
  const { createPasskey } = await import("./passkey.js");
  const { credentialId, secret } = await createPasskey(vault.email);
  const { encKey, authKey } = await derivePasskeyKeys(secret);
  secret.fill(0);

  await api.addPasskey({
    credentialId,
    authKey,
    wrappedKey: await wrapVaultKey(encKey, keys.vault),
    label: label || "Passkey",
  });
}

/** Signs in and opens the vault with a passkey, with nothing typed. */
export async function unlockWithPasskey() {
  const { usePasskey } = await import("./passkey.js");
  const { credentialId, secret } = await usePasskey();
  const { encKey, authKey } = await derivePasskeyKeys(secret);
  secret.fill(0);

  const result = await api.passkeyLogin({ credentialId, authKey, deviceId: deviceId() });

  keys.vault = await unwrapVaultKey(encKey, result.wrappedKey);
  adopt(result);
  await load();

  return {
    devicesSignedOut: result.devicesSignedOut ?? 0,
    deviceLimit: result.deviceLimit ?? null,
  };
}

// --- recovery ---------------------------------------------------------------

/**
 * Step one: prove possession of the Recovery Key and open the vault key with it.
 *
 * The server hands back the recovery-wrapped copy of the vault key. Unwrapping
 * happens here, so at no point does anything capable of decrypting the vault
 * exist on the server side.
 */
export async function recoverStart(email, recoveryKey) {
  const address = normalizeEmail(email);
  const recovery = await deriveRecoveryKeys(recoveryKey, address);

  const result = await api.recover({ email: address, recoveryAuthKey: recovery.authKey });

  let vaultKey;
  try {
    vaultKey = await unwrapVaultKey(recovery.encKey, result.recoveryWrap);
  } catch {
    throw new Error("That Recovery Key did not open the vault.");
  }

  recoveryState = { email: result.email, vaultKey };
  return result.email;
}

/**
 * Step two: set a new master password, and mint a fresh Recovery Key because the
 * old one has now been typed into a browser.
 */
export async function recoverComplete(newPassword) {
  if (!recoveryState) throw new Error("Start the recovery process again.");

  const { email, vaultKey } = recoveryState;
  const iterations = DEFAULT_KDF_ITERATIONS;
  const recoveryKey = generateRecoveryKey();

  const [account, recovery] = await Promise.all([
    deriveAccountKeys(newPassword, email, iterations),
    deriveRecoveryKeys(recoveryKey, email),
  ]);

  await api.recoverComplete({
    authKey: account.authKey,
    kdfIterations: iterations,
    protectedKey: await wrapVaultKey(account.encKey, vaultKey),
    recoveryWrap: await wrapVaultKey(recovery.encKey, vaultKey),
    recoveryAuthKey: recovery.authKey,
  });

  recoveryState = null;
  return recoveryKey;
}

/** Issues a replacement Recovery Key without touching the master password. */
export async function rotateRecoveryKey(currentPassword) {
  const { authKey } = await deriveAccountKeys(
    currentPassword,
    vault.email,
    vault.kdfIterations,
  );
  const recoveryKey = generateRecoveryKey();
  const recovery = await deriveRecoveryKeys(recoveryKey, vault.email);

  await api.rotateRecoveryKey({
    currentAuthKey: authKey,
    recoveryWrap: await wrapVaultKey(recovery.encKey, keys.vault),
    recoveryAuthKey: recovery.authKey,
  });

  vault.hasRecoveryKey = true;
  emit();
  return recoveryKey;
}

/**
 * The last resort, for an account with neither password nor Recovery Key.
 * This destroys the vault. There is nothing else it could do.
 */
export async function resetConfirm(token, email, newPassword) {
  const address = normalizeEmail(email);
  const iterations = DEFAULT_KDF_ITERATIONS;

  const vaultKey = await generateVaultKey();
  const recoveryKey = generateRecoveryKey();

  const [account, recovery] = await Promise.all([
    deriveAccountKeys(newPassword, address, iterations),
    deriveRecoveryKeys(recoveryKey, address),
  ]);

  await api.resetConfirm({
    token,
    authKey: account.authKey,
    kdfIterations: iterations,
    protectedKey: await wrapVaultKey(account.encKey, vaultKey),
    recoveryWrap: await wrapVaultKey(recovery.encKey, vaultKey),
    recoveryAuthKey: recovery.authKey,
  });

  return recoveryKey;
}

// --- items ------------------------------------------------------------------

export async function load() {
  const { items } = await api.listItems(0);
  const decrypted = [];

  for (const row of items) {
    try {
      decrypted.push(toItem(row, await decryptItem(keys.vault, row.data)));
    } catch {
      // One unreadable row must not take the whole vault down with it. Surface
      // it as a broken item so it can be seen and dealt with, rather than
      // silently vanishing.
      decrypted.push(toItem(row, { name: "Unreadable item", broken: true }));
    }
  }

  vault.items = decrypted.sort(byName);
  vault.itemCount = decrypted.filter((item) => !item.deletedAt).length;
  emit();
  return vault.items;
}

const byName = (a, b) =>
  (a.name ?? "").localeCompare(b.name ?? "", undefined, { sensitivity: "base" });

function toItem(row, content) {
  return {
    id: row.id,
    revision: row.revision,
    createdAt: row.createdAt,
    updatedAt: row.updatedAt,
    deletedAt: row.deletedAt,
    name: "",
    username: "",
    password: "",
    url: "",
    notes: "",
    totp: "",
    favorite: false,
    folder: "",
    history: [],
    ...content,
  };
}

const contentOf = (item) => Object.fromEntries(CONTENT_FIELDS.map((k) => [k, item[k]]));

export async function saveItem(draft) {
  const now = Date.now();
  const existing = draft.id ? vault.items.find((item) => item.id === draft.id) : null;
  const item = { ...(existing ?? {}), ...draft };

  // Keep a short history of replaced passwords, so a change that locks someone
  // out of a site is recoverable.
  if (existing && existing.password && existing.password !== item.password) {
    item.history = [
      { password: existing.password, changedAt: now },
      ...(existing.history ?? []),
    ].slice(0, 5);
    item.passwordUpdatedAt = now;
  } else if (!existing) {
    item.passwordUpdatedAt = now;
    item.history = [];
  }

  const blob = await encryptItem(keys.vault, contentOf(item));

  if (existing) {
    const result = await api.updateItem(existing.id, blob, existing.revision);
    Object.assign(item, { revision: result.revision, updatedAt: result.updatedAt });
    vault.items = vault.items.map((row) => (row.id === item.id ? item : row)).sort(byName);
  } else {
    const result = await api.createItem(blob);
    Object.assign(item, {
      id: result.id,
      revision: result.revision,
      createdAt: result.createdAt,
      updatedAt: result.updatedAt,
      deletedAt: null,
    });
    vault.items = [...vault.items, item].sort(byName);
  }

  vault.itemCount = vault.items.filter((row) => !row.deletedAt).length;
  emit();
  return item;
}

async function mutate(id, call, patch) {
  await call(id);
  vault.items = vault.items.map((item) => (item.id === id ? { ...item, ...patch } : item));
  vault.itemCount = vault.items.filter((row) => !row.deletedAt).length;
  emit();
}

export const deleteItem = (id) => mutate(id, api.deleteItem, { deletedAt: Date.now() });
export const restoreItem = (id) => mutate(id, api.restoreItem, { deletedAt: null });

export async function purgeItem(id) {
  await api.purgeItem(id);
  vault.items = vault.items.filter((item) => item.id !== id);
  emit();
}

export async function emptyTrash() {
  const result = await api.emptyTrash();
  vault.items = vault.items.filter((item) => !item.deletedAt);
  emit();
  return result.purged;
}

// --- account ----------------------------------------------------------------

/**
 * Change the master password.
 *
 * The vault key does not change, so items are left alone. We re-wrap that one
 * key and hand the server a new verifier. The Recovery Key still works, because
 * it wraps the same unchanged vault key.
 */
export async function changeMasterPassword(currentPassword, nextPassword) {
  const current = await deriveAccountKeys(currentPassword, vault.email, vault.kdfIterations);
  const iterations = DEFAULT_KDF_ITERATIONS;
  const next = await deriveAccountKeys(nextPassword, vault.email, iterations);

  await api.rekey({
    currentAuthKey: current.authKey,
    authKey: next.authKey,
    kdfIterations: iterations,
    protectedKey: await wrapVaultKey(next.encKey, keys.vault),
  });

  vault.kdfIterations = iterations;
  emit();
}

/**
 * Change the address on the account.
 *
 * The email is the KDF salt, so everything derived from the master password has
 * to be rebuilt against the new address. The vault key itself is unchanged, so
 * items are not re-encrypted. A new Recovery Key is issued and returned, because
 * the old one was salted with the old address and would no longer work.
 */
export async function changeEmail(currentPassword, newEmail) {
  const current = await deriveAccountKeys(currentPassword, vault.email, vault.kdfIterations);
  const address = normalizeEmail(newEmail);
  const iterations = DEFAULT_KDF_ITERATIONS;
  const recoveryKey = generateRecoveryKey();

  const [next, recovery] = await Promise.all([
    deriveAccountKeys(currentPassword, address, iterations),
    deriveRecoveryKeys(recoveryKey, address),
  ]);

  await api.changeEmail({
    currentAuthKey: current.authKey,
    email: address,
    authKey: next.authKey,
    kdfIterations: iterations,
    protectedKey: await wrapVaultKey(next.encKey, keys.vault),
    recoveryWrap: await wrapVaultKey(recovery.encKey, keys.vault),
    recoveryAuthKey: recovery.authKey,
  });

  Object.assign(vault, {
    email: address,
    kdfIterations: iterations,
    emailVerified: false,
    recoveryCreatedAt: Date.now(),
  });
  emit();
  return recoveryKey;
}

export async function authKeyFor(masterPassword) {
  const { authKey } = await deriveAccountKeys(masterPassword, vault.email, vault.kdfIterations);
  return authKey;
}

export async function refreshAccount() {
  const account = await api.me();
  Object.assign(vault, {
    emailVerified: Boolean(account.emailVerified),
    hasRecoveryKey: account.hasRecoveryKey,
    recoveryCreatedAt: account.recoveryCreatedAt,
    plan: account.plan,
    planStatus: account.planStatus,
    planPeriodEnd: account.planPeriodEnd,
    itemCount: account.itemCount,
  });
  emit();
  return account;
}

// --- backup -----------------------------------------------------------------

export async function exportBackup(passphrase) {
  return encryptBackup(passphrase, {
    exportedAt: new Date().toISOString(),
    items: vault.items.filter((item) => !item.deletedAt).map(contentOf),
  });
}

export async function importBackup(passphrase, file) {
  const payload = await decryptBackup(passphrase, file);
  if (!Array.isArray(payload.items)) throw new Error("That backup contains no items.");

  const blobs = await Promise.all(
    payload.items.map((content) => encryptItem(keys.vault, contentOf(toItem({}, content)))),
  );
  const result = await api.bulkCreate(blobs.map((data) => ({ data })));
  await load();
  return result.created;
}

/**
 * Import from another manager's CSV.
 *
 * Handles the common export shapes (LastPass, Bitwarden, 1Password, Chrome) by
 * matching on column name rather than position, since every one of them differs.
 */
export async function importCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error("That file has no rows in it.");

  const header = rows[0].map((cell) => cell.trim().toLowerCase());
  const find = (...names) => {
    for (const name of names) {
      const index = header.indexOf(name);
      if (index !== -1) return index;
    }
    return -1;
  };

  const columns = {
    name: find("name", "title", "account", "item name"),
    url: find("url", "login_uri", "uri", "website", "login uri"),
    username: find("username", "login_username", "user name", "login", "email"),
    password: find("password", "login_password"),
    notes: find("notes", "note", "extra"),
    totp: find("totp", "login_totp", "otpauth", "authenticator key"),
  };
  if (columns.password === -1 && columns.username === -1) {
    throw new Error("That file has no username or password column.");
  }

  const at = (row, index) => (index === -1 ? "" : (row[index] ?? "").trim());
  const items = rows
    .slice(1)
    .filter((row) => row.some((cell) => cell.trim()))
    .map((row) =>
      toItem(
        {},
        {
          name: at(row, columns.name) || at(row, columns.url) || "Untitled",
          url: at(row, columns.url),
          username: at(row, columns.username),
          password: at(row, columns.password),
          notes: at(row, columns.notes),
          totp: at(row, columns.totp),
          passwordUpdatedAt: Date.now(),
        },
      ),
    );

  const blobs = await Promise.all(items.map((item) => encryptItem(keys.vault, contentOf(item))));
  const result = await api.bulkCreate(blobs.map((data) => ({ data })));
  await load();
  return result.created;
}

/** RFC 4180 enough for real exports: quoted fields, embedded commas and newlines. */
function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let quoted = false;

  const source = text.replace(/^﻿/, "").replace(/\r\n/g, "\n");
  for (let i = 0; i < source.length; i++) {
    const char = source[i];
    if (quoted) {
      if (char === '"') {
        if (source[i + 1] === '"') {
          field += '"';
          i++;
        } else quoted = false;
      } else field += char;
    } else if (char === '"') quoted = true;
    else if (char === ",") {
      row.push(field);
      field = "";
    } else if (char === "\n") {
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else field += char;
  }
  if (field || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows;
}

export { ApiError };
