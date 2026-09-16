/**
 * The popup.
 *
 * It holds no keys and no secrets. Every request goes to the service worker,
 * which hands back a single value only when the user has asked to copy that
 * specific one. Filling never comes through here at all.
 */

const $ = (id) => document.getElementById(id);

const send = (type, payload = {}) =>
  chrome.runtime.sendMessage({ type, ...payload }).then((reply) => {
    if (reply?.error) {
      const error = new Error(reply.message ?? "Something went wrong.");
      error.code = reply.error;
      throw error;
    }
    return reply;
  });

let currentHost = "";
let toastTimer = null;

function toast(message) {
  const node = $("toast");
  node.textContent = message;
  node.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    node.hidden = true;
  }, 1800);
}

function show(view) {
  for (const id of ["loading", "unlock", "vault"]) $(id).hidden = id !== view;
  $("lock").hidden = view !== "vault";
}

// --- start ------------------------------------------------------------------

start();

async function start() {
  let state;
  try {
    state = await send("state");
  } catch {
    show("unlock");
    fail("Could not reach the extension background. Try reopening the popup.");
    return;
  }

  currentHost = state.host ?? "";

  if (state.locked) {
    show("unlock");
    if (currentHost) {
      $("unlock-note").textContent = `Unlock to fill passwords on ${currentHost}.`;
    }
    $("email").focus();
    return;
  }

  $("account").textContent = `${state.email} · locks after ${state.lockMinutes} min idle`;
  $("capture").checked = state.capture;
  show("vault");
  await Promise.all([refresh(), showOffer()]);
  $("search").focus();
}

// --- save on submit ---------------------------------------------------------

let offerId = null;

async function showOffer() {
  const { offer } = await send("offer");
  offerId = offer?.id ?? null;
  $("offer").hidden = !offer;
  if (!offer) return;

  const who = offer.username ? `${offer.username} on ${offer.host}` : offer.host;
  $("offer-text").textContent =
    offer.kind === "update"
      ? `Update the saved password for ${who}?`
      : `Save the login you just used for ${who}?`;
  $("offer-accept").textContent = offer.kind === "update" ? "Update" : "Save";
}

async function answerOffer(action, extra = {}) {
  if (!offerId) return;
  try {
    const result = await send(action, { id: offerId, ...extra });
    if (action === "acceptOffer") {
      toast(result.kind === "update" ? "Password updated" : "Login saved");
      await refresh();
    }
  } catch (error) {
    toast(error.message);
  }
  await showOffer();
}

$("offer-accept").addEventListener("click", () => answerOffer("acceptOffer"));
$("offer-later").addEventListener("click", () => answerOffer("dismissOffer"));
$("offer-never").addEventListener("click", () => answerOffer("dismissOffer", { never: true }));

/**
 * Turning this on needs access to every https site, so the browser is asked
 * for it here, as the direct result of the click. Firefox refuses a request
 * that is not, which is why nothing is awaited before it.
 */
$("capture").addEventListener("change", async (event) => {
  const box = event.target;
  let on = box.checked;
  if (on) {
    try {
      on = await chrome.permissions.request({ origins: ["https://*/*"] });
    } catch {
      on = false;
    }
  }
  try {
    const result = await send("setCapture", { on });
    box.checked = result.capture;
    toast(result.capture ? "KalmPass will offer to save new logins" : "Save offers are off");
  } catch (error) {
    box.checked = false;
    toast(error.message);
  }
});

// --- unlocking --------------------------------------------------------------

function fail(message) {
  const node = $("unlock-error");
  node.textContent = message;
  node.hidden = false;
}

$("unlock").addEventListener("submit", async (event) => {
  event.preventDefault();

  const button = $("unlock-submit");
  $("unlock-error").hidden = true;
  button.disabled = true;
  button.textContent = "Unlocking...";

  const usingBackup = $("totp-label").dataset.mode === "backup";
  const code = $("totp").value.trim();

  try {
    const outcome = await send("unlock", {
      email: $("email").value,
      password: $("password").value,
      ...(code && !usingBackup ? { totp: code } : {}),
      ...(code && usingBackup ? { backupCode: code } : {}),
    });
    $("password").value = "";
    await start();

    if (outcome?.devicesSignedOut > 0) {
      const n = outcome.devicesSignedOut;
      toast(
        `Signed out ${n} other device${n === 1 ? "" : "s"} (plan covers ${outcome.deviceLimit}).`,
      );
    }
  } catch (error) {
    if (error.code === "totp_required" || error.code === "totp_invalid") {
      $("totp-field").hidden = false;
      $("use-backup").hidden = false;
      $("totp").focus();
      if (error.code === "totp_invalid") fail(error.message);
    } else {
      fail(
        error.name === "OperationError"
          ? "That master password does not open this vault."
          : error.message,
      );
    }
  } finally {
    button.disabled = false;
    button.textContent = "Unlock";
  }
});

$("use-backup").addEventListener("click", () => {
  const label = $("totp-label");
  const backup = label.dataset.mode !== "backup";
  label.dataset.mode = backup ? "backup" : "totp";
  label.textContent = backup ? "Backup code" : "Authenticator code";
  $("use-backup").textContent = backup
    ? "Use my authenticator app instead"
    : "Use a backup code instead";
  $("totp").value = "";
  $("totp").focus();
});

$("lock").addEventListener("click", async () => {
  await send("lock");
  location.reload();
});

// --- the list ---------------------------------------------------------------

$("search").addEventListener("input", () => refresh());

async function refresh() {
  const { items } = await send("list", { query: $("search").value, host: currentHost });
  const list = $("list");
  list.replaceChildren();

  if (items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "empty";
    empty.textContent = $("search").value
      ? "Nothing matches that."
      : "Your vault is empty.";
    list.append(empty);
    return;
  }

  for (const item of items) list.append(row(item));
}

function button(label, className, onClick) {
  const node = document.createElement("button");
  node.type = "button";
  node.textContent = label;
  if (className) node.className = className;
  node.addEventListener("click", onClick);
  return node;
}

function row(item) {
  const li = document.createElement("li");
  li.dataset.here = String(item.onThisSite);

  const main = document.createElement("div");
  main.className = "row-main";

  const name = document.createElement("div");
  name.className = "name";
  name.textContent = item.name;

  const sub = document.createElement("div");
  sub.className = "sub";
  sub.textContent = [item.username, item.host].filter(Boolean).join(" · ") || "No username";

  main.append(name, sub);

  const head = document.createElement("div");
  head.className = "row";
  head.append(main);

  if (item.onThisSite) {
    const flag = document.createElement("span");
    flag.className = "here";
    flag.textContent = "this site";
    head.append(flag);
  }

  const actions = document.createElement("div");
  actions.className = "actions";

  actions.append(
    button("Fill", "go", () => fillItem(item, actions)),
    button("Copy password", null, () => copy(item.id, "password", "Password copied")),
    button("Copy user", null, () => copy(item.id, "username", "Username copied")),
  );

  if (item.hasTotp) {
    actions.append(button("Copy code", null, () => copy(item.id, "totp", "Code copied")));
  }

  li.append(head, actions);
  return li;
}

async function fillItem(item, actions, anyway = false) {
  try {
    await send("fill", { id: item.id, anyway });
    // Closing afterwards puts the focus back on the page, which is where
    // somebody who just filled a login wants to be.
    window.close();
  } catch (error) {
    if (error.code === "host_mismatch" || error.code === "insecure_page") {
      askFirst(item, actions, error.message);
    } else {
      toast(error.message);
    }
  }
}

/**
 * Asked inline rather than with confirm(), which Firefox does not allow in a
 * popup and Chrome answers by closing it.
 */
function askFirst(item, actions, message) {
  const original = [...actions.childNodes];
  const note = document.createElement("p");
  note.className = "warn";
  note.setAttribute("role", "alert");
  note.textContent = message;
  actions.replaceChildren(
    note,
    button("Fill anyway", "danger", () => fillItem(item, actions, true)),
    button("Cancel", null, () => actions.replaceChildren(...original)),
  );
}

/**
 * The secret is fetched, written to the clipboard, and dropped. It is never
 * held in the popup's state and never rendered to the screen.
 */
async function copy(id, field, message) {
  try {
    const { value } = await send("secret", { id, field });
    await navigator.clipboard.writeText(value);
    toast(message);
  } catch (error) {
    toast(error.message);
  }
}
