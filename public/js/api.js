/** Thin wrapper over fetch. Everything it sends is already ciphertext. */

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
    response = await fetch(`/api${path}`, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      // The session cookie is HttpOnly and SameSite=Strict; this is here to be
      // explicit that credentials never go anywhere else.
      credentials: "same-origin",
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

export const api = {
  status: () => request("GET", "/account/status"),
  prelogin: (email) => request("POST", "/account/prelogin", { email }),
  signup: (body) => request("POST", "/account/signup", body),
  login: (body) => request("POST", "/account/login", body),
  logout: () => request("POST", "/account/logout"),
  me: () => request("GET", "/account"),

  verifyEmail: (token) => request("POST", "/account/verify", { token }),
  resendVerification: () => request("POST", "/account/resend-verification"),

  rekey: (body) => request("POST", "/account/rekey", body),
  changeEmail: (body) => request("POST", "/account/email", body),
  recover: (body) => request("POST", "/account/recover", body),
  recoverComplete: (body) => request("POST", "/account/recover/complete", body),
  rotateRecoveryKey: (body) => request("POST", "/account/recovery-key/rotate", body),
  resetRequest: (email) => request("POST", "/account/reset/request", { email }),
  resetConfirm: (body) => request("POST", "/account/reset/confirm", body),
  deleteAccount: (body) => request("DELETE", "/account", body),

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

  breachRange: (prefix) => request("POST", "/tools/breach", { prefix }),
};
