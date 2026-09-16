/** Thin wrapper over fetch. Everything it sends is already ciphertext. */

import { API_ORIGIN, isNative } from "./platform.js";

/**
 * The apps cannot use the session cookie, so they hold the session token here,
 * in memory only, as the browser extension does. Closing the app ends it.
 */
let bearer = null;

export class ApiError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    Object.assign(this, extra);
  }
}

async function request(method, path, body) {
  let response;
  try {
    response = await fetch(`${API_ORIGIN}/api${path}`, {
      method,
      headers: {
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(bearer ? { authorization: `Bearer ${bearer}` } : {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      // The session cookie is HttpOnly and SameSite=Strict; this is here to be
      // explicit that credentials never go anywhere else. The apps send none.
      credentials: isNative ? "omit" : "same-origin",
      cache: "no-store",
      redirect: "error",
    });
  } catch {
    throw new ApiError(0, "offline", "Could not reach the server.");
  }

  if (response.status === 204) return null;

  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new ApiError(response.status, "bad_response", "The server sent an unreadable reply.");
  }

  if (!response.ok) {
    const { error, message, ...extra } = payload ?? {};
    throw new ApiError(response.status, error ?? "error", message ?? "Something went wrong.", extra);
  }
  return payload;
}

/**
 * Calls that start a session. In the apps they ask for the token in the reply
 * and keep it; on the website the server sets the cookie as before.
 */
const opensSession = (path) => async (body) => {
  const reply = await request("POST", path, isNative ? { ...body, tokenAuth: true } : body);
  if (reply?.token) {
    bearer = reply.token;
    delete reply.token;
  }
  return reply;
};

/** Calls that end the session they were made with. */
const closesSession = (method, path) => async (body) => {
  try {
    return await request(method, path, body);
  } finally {
    bearer = null;
  }
};

export const api = {
  forgetToken: () => {
    bearer = null;
  },

  status: () => request("GET", "/account/status"),
  prelogin: (email) => request("POST", "/account/prelogin", { email }),
  signup: opensSession("/account/signup"),
  login: opensSession("/account/login"),
  logout: closesSession("POST", "/account/logout"),
  me: () => request("GET", "/account"),

  verifyEmail: (token) => request("POST", "/account/verify", { token }),
  resendVerification: () => request("POST", "/account/resend-verification"),

  rekey: (body) => request("POST", "/account/rekey", body),
  changeEmail: (body) => request("POST", "/account/email", body),
  recover: opensSession("/account/recover"),
  recoverComplete: closesSession("POST", "/account/recover/complete"),
  rotateRecoveryKey: (body) => request("POST", "/account/recovery-key/rotate", body),
  resetRequest: (email) => request("POST", "/account/reset/request", { email }),
  resetConfirm: (body) => request("POST", "/account/reset/confirm", body),
  deleteAccount: closesSession("DELETE", "/account"),

  passkeys: () => request("GET", "/account/passkeys"),
  addPasskey: (body) => request("POST", "/account/passkeys", body),
  removePasskey: (id) => request("DELETE", `/account/passkeys/${id}`),
  passkeyLogin: opensSession("/account/passkey-login"),

  totpStart: () => request("POST", "/account/totp/start"),
  totpEnable: (code) => request("POST", "/account/totp/enable", { code }),
  totpDisable: (currentAuthKey) => request("POST", "/account/totp/disable", { currentAuthKey }),

  sessions: () => request("GET", "/account/sessions"),
  revokeSessions: () => request("DELETE", "/account/sessions"),
  activity: () => request("GET", "/account/activity"),

  checkout: () => request("POST", "/billing/checkout"),
  portal: () => request("POST", "/billing/portal"),

  listItems: (since = 0) => request("GET", `/items?since=${since}`),
  createItem: (data) => request("POST", "/items", { data }),
  updateItem: (id, data, revision) => request("PUT", `/items/${id}`, { data, revision }),
  deleteItem: (id) => request("DELETE", `/items/${id}`),
  restoreItem: (id) => request("POST", `/items/${id}/restore`),
  purgeItem: (id) => request("DELETE", `/items/${id}/purge`),
  emptyTrash: () => request("DELETE", "/items/trash"),
  bulkCreate: (items) => request("POST", "/items/bulk", { items }),

  exposedRange: (prefix) => request("POST", "/tools/exposed-passwords", { prefix }),
};
