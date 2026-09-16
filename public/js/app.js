/**
 * Bootstrap: pick a screen, run the sign-in and recovery flows, wire the
 * toolbar, and lock the vault again when it has been sitting idle.
 */

import { api } from "./api.js";
import { $, el, focus, show } from "./dom.js";
import { estimateStrength, generatePassphrase } from "./generator.js";
import { openSettings, prefs } from "./settings.js";
import * as store from "./store.js";
import { isEmail } from "./validate.js";
import { vault } from "./store.js";
import { hasPlatformAuthenticator, isSupported } from "./passkey.js";
import { APP_HOME, isNative, saveFile } from "./platform.js";
import { biometryName } from "./settings.js";
import { copy, guard, toast } from "./ui.js";
import { openEditor, openGenerator, render, updateMeter, view } from "./vault-view.js";

const AUTH_VIEWS = [
  "signin",
  "signup",
  "kit",
  "recover",
  "recover-set",
  "reset",
  "reset-set",
];

const TAGLINES = {
  signin: "Your vault, locked to your master password.",
  signup: "One password to remember. Everything else, we handle.",
  kit: "Save this before you go any further.",
  recover: "Let us get you back in.",
  "recover-set": "Almost there.",
  reset: "The last resort.",
  "reset-set": "This cannot be undone.",
};

let resumeMode = false;
let pendingTotp = false;
let instanceStatus = { signupAllowed: true, setupCodeRequired: false };

function showScreen(name) {
  show($("#boot"), name === "boot");
  show($("#screen-auth"), name === "auth");
  show($("#screen-vault"), name === "vault");
}

function showAuthView(name) {
  for (const id of AUTH_VIEWS) show($(`#view-${id}`), id === name);
  $("#auth-tagline").textContent = TAGLINES[name] ?? "";
  showScreen("auth");
  focus($(`#view-${name}`)?.querySelector("input:not([type=checkbox])"));
}

for (const button of document.querySelectorAll("[data-go]")) {
  button.addEventListener("click", () => showAuthView(button.dataset.go));
}

// --- start ------------------------------------------------------------------

async function start() {
  prefs.load();

  // Offered only where it can actually work, rather than dangled and then
  // failing once the authenticator turns out not to support PRF. The apps
  // have their own way in, through the phone's secure storage.
  if (!isNative && isSupported() && (await hasPlatformAuthenticator())) {
    show($("#signin-passkey"), true);
  }
  show($("#kit-print"), !isNative);

  const params = new URLSearchParams(location.search);
  const clean = () => history.replaceState(null, "", APP_HOME);

  try {
    instanceStatus = await api.status();
  } catch {
    $("#boot").replaceChildren(
      el("p", {
        class: "boot-text",
        text: "Could not reach KalmPass. Check your connection and reload.",
      }),
    );
    return;
  }

  show($("#signup-invite-field"), Boolean(instanceStatus.setupCodeRequired));

  // Arriving from the account-reset email.
  if (params.get("reset")) {
    resetToken = params.get("reset");
    clean();
    showAuthView("reset-set");
    return;
  }

  // Arriving from the confirm-your-email link. Doing this before anything else
  // means the account is confirmed even if the person then closes the tab.
  if (params.get("verify")) {
    try {
      await api.verifyEmail(params.get("verify"));
      toast("Email confirmed");
    } catch (error) {
      toast(error.message, "bad");
    }
    clean();
  }

  if (params.get("billing") === "success") {
    toast("You are on Pro. Thank you.");
    clean();
  } else if (params.get("billing") === "cancelled") {
    clean();
  }

  const account = await store.hasServerSession();
  if (account) {
    // A live server session means the browser only needs the master password
    // again to rebuild the keys, no second session, no second login.
    $("#signin-email").value = account.email;
    resumeMode = true;
    showAuthView("signin");
    $("#auth-tagline").textContent = "Welcome back. Enter your master password to unlock.";
    focus($("#signin-password"));
    return;
  }

  showAuthView(params.get("new") === "1" && instanceStatus.signupAllowed ? "signup" : "signin");

  if (isNative) {
    const device = await store.deviceUnlockStatus();
    if (device.enabled) {
      const button = $("#signin-device");
      button.dataset.label = `Unlock with ${biometryName(device.biometry)}`;
      button.textContent = button.dataset.label;
      show(button, true);
      // Opening the app is the request to unlock it, so ask straight away.
      unlockWithDevice();
    }
  }
}

// --- sign in ----------------------------------------------------------------

$("#view-signin").addEventListener("submit", async (event) => {
  event.preventDefault();

  const error = $("#signin-error");
  const submit = $("#signin-submit");
  const code = $("#signin-totp").value.trim();
  const useBackup = $("#signin-totp-label").dataset.mode === "backup";

  error.hidden = true;
  submit.disabled = true;
  submit.textContent = "Unlocking…";

  try {
    let outcome;
    if (resumeMode && !pendingTotp) {
      await store.resume($("#signin-password").value);
    } else {
      outcome = await store.unlock($("#signin-email").value.trim(), $("#signin-password").value, {
        ...(code && !useBackup ? { totp: code } : {}),
        ...(code && useBackup ? { backupCode: code } : {}),
      });
    }
    enterVault();

    if (outcome?.devicesSignedOut > 0) {
      const n = outcome.devicesSignedOut;
      toast(
        `Signed out ${n} other device${n === 1 ? "" : "s"}. Your plan covers ${outcome.deviceLimit}.`,
      );
    }
  } catch (err) {
    if (err.code === "totp_required" || err.code === "totp_invalid") {
      pendingTotp = true;
      resumeMode = false;
      show($("#signin-totp-field"), true);
      show($("#signin-use-backup"), true);
      focus($("#signin-totp"));
      if (err.code === "totp_invalid") fail(error, err.message);
    } else {
      fail(
        error,
        err.name === "OperationError" || err.code === "decrypt_failed"
          ? "That master password does not open this vault."
          : err.message,
      );
      $("#signin-password").select();
    }
  } finally {
    submit.disabled = false;
    submit.textContent = "Unlock";
  }
});

$("#signin-passkey").addEventListener("click", async () => {
  const button = $("#signin-passkey");
  const error = $("#signin-error");
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Waiting for your passkey...";

  try {
    const outcome = await store.unlockWithPasskey();
    enterVault();
    if (outcome?.devicesSignedOut > 0) {
      const n = outcome.devicesSignedOut;
      toast(`Signed out ${n} other device${n === 1 ? "" : "s"}.`);
    }
  } catch (err) {
    // A cancelled prompt is a decision, not a failure worth shouting about.
    if (err?.name !== "NotAllowedError" && err?.name !== "AbortError") {
      fail(error, err.message ?? "That passkey did not work.");
    }
  } finally {
    button.disabled = false;
    button.textContent = "Unlock with a passkey";
  }
});

async function unlockWithDevice() {
  const button = $("#signin-device");
  const error = $("#signin-error");
  error.hidden = true;
  button.disabled = true;

  try {
    const outcome = await store.unlockWithDevice();
    enterVault();
    if (outcome?.devicesSignedOut > 0) {
      const n = outcome.devicesSignedOut;
      toast(`Signed out ${n} other device${n === 1 ? "" : "s"}.`);
    }
  } catch (err) {
    if (err?.code !== "cancelled") fail(error, err.message ?? "That did not unlock the vault.");
    if (err?.code === "invalidated" || /turned off/.test(err?.message ?? "")) show(button, false);
  } finally {
    button.disabled = false;
  }
}

$("#signin-device").addEventListener("click", unlockWithDevice);

$("#signin-use-backup").addEventListener("click", () => {
  const label = $("#signin-totp-label");
  const backup = label.dataset.mode !== "backup";
  label.dataset.mode = backup ? "backup" : "totp";
  label.textContent = backup ? "Backup code" : "Authenticator code";
  $("#signin-use-backup").textContent = backup
    ? "Use my authenticator app instead"
    : "Use a backup code instead";
  $("#signin-totp").value = "";
  focus($("#signin-totp"));
});

// --- sign up ----------------------------------------------------------------

const fail = (node, message) => {
  node.textContent = message;
  node.hidden = false;
};

$("#signup-password").addEventListener("input", () =>
  updateMeter($("#signup-meter"), $("#signup-password").value),
);

$("#signup-suggest").addEventListener("click", () => {
  const suggestion = generatePassphrase({ words: 5 });
  $("#signup-password").value = suggestion;
  $("#signup-confirm").value = suggestion;
  $("#signup-password").setAttribute("type", "text");
  $("#signup-confirm").setAttribute("type", "text");
  updateMeter($("#signup-meter"), suggestion);
  toast("Write this down before you continue");
});

$("#view-signup").addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = $("#signup-email").value.trim();
  const password = $("#signup-password").value;
  const error = $("#signup-error");
  const submit = $("#signup-submit");
  error.hidden = true;

  if (!isEmail(email)) return fail(error, "Enter a valid email address.");
  if (password !== $("#signup-confirm").value) return fail(error, "The passwords do not match.");
  if (password.length < 12) return fail(error, "Use at least 12 characters.");
  if (estimateStrength(password).score < 2) {
    return fail(error, "Choose something stronger. Everything rests on this one password.");
  }
  if (!$("#signup-ack").checked) return fail(error, "Please confirm you understand.");

  submit.disabled = true;
  submit.textContent = "Creating…";
  try {
    const recoveryKey = await store.signup(email, password, $("#signup-invite").value.trim());
    showKit(recoveryKey, email, () => {
      enterVault();
      toast("Vault created. Check your email to confirm your address.");
    });
  } catch (err) {
    fail(error, err.message);
  } finally {
    submit.disabled = false;
    submit.textContent = "Create my vault";
  }
});

// --- the Emergency Kit ------------------------------------------------------

let kitContinue = null;

function showKit(recoveryKey, email, onContinue) {
  $("#kit-key").textContent = recoveryKey;
  $("#kit-ack").checked = false;
  $("#kit-continue").disabled = true;
  $("#kit-key").dataset.email = email;
  kitContinue = onContinue;
  showAuthView("kit");
}

$("#kit-ack").addEventListener("change", (event) => {
  $("#kit-continue").disabled = !event.target.checked;
});

$("#kit-copy").addEventListener("click", () =>
  copy($("#kit-key").textContent, "Recovery Key copied"),
);

$("#kit-download").addEventListener("click", () => {
  const key = $("#kit-key").textContent;
  const email = $("#kit-key").dataset.email;
  const content = [
    "KalmPass Emergency Kit",
    "======================",
    "",
    `Account:      ${email}`,
    `Recovery Key: ${key}`,
    `Issued:       ${new Date().toISOString()}`,
    "",
    "What this is for",
    "----------------",
    "If you forget your master password, this key is the only way back into",
    "your vault. Go to https://kalmpass.net/app/ and choose \"Forgot your",
    "master password?\".",
    "",
    "Keep this somewhere safe and offline, a printed copy in a drawer, or a",
    "safe. Do not store it in the vault it protects.",
    "",
    "KalmPass cannot read your vault and cannot reset your master password.",
    "Nobody from KalmPass will ever ask you for this key.",
    "",
  ].join("\n");

  guard(() => saveFile("kalmpass-emergency-kit.txt", content, "text/plain"))();
});

$("#kit-print").addEventListener("click", () => window.print());
$("#kit-continue").addEventListener("click", () => kitContinue?.());

// --- recovery ---------------------------------------------------------------

$("#view-recover").addEventListener("submit", async (event) => {
  event.preventDefault();

  const error = $("#recover-error");
  const submit = $("#recover-submit");
  error.hidden = true;
  submit.disabled = true;
  submit.textContent = "Checking…";

  try {
    await store.recoverStart($("#recover-email").value.trim(), $("#recover-key").value);
    showAuthView("recover-set");
  } catch (err) {
    fail(error, err.message);
  } finally {
    submit.disabled = false;
    submit.textContent = "Continue";
  }
});

$("#recover-password").addEventListener("input", () =>
  updateMeter($("#recover-meter"), $("#recover-password").value),
);

$("#view-recover-set").addEventListener("submit", async (event) => {
  event.preventDefault();

  const password = $("#recover-password").value;
  const error = $("#recover-set-error");
  const submit = $("#recover-set-submit");
  error.hidden = true;

  if (password !== $("#recover-confirm").value) return fail(error, "The passwords do not match.");
  if (password.length < 12) return fail(error, "Use at least 12 characters.");
  if (estimateStrength(password).score < 2) return fail(error, "Choose something stronger.");

  submit.disabled = true;
  submit.textContent = "Setting…";
  try {
    const recoveryKey = await store.recoverComplete(password);
    showKit(recoveryKey, $("#recover-email").value.trim(), () => {
      $("#signin-email").value = $("#recover-email").value.trim();
      resumeMode = false;
      showAuthView("signin");
      toast("Password changed. Sign in with it now.");
    });
  } catch (err) {
    fail(error, err.message);
  } finally {
    submit.disabled = false;
    submit.textContent = "Set password";
  }
});

// --- account reset ----------------------------------------------------------

let resetToken = null;

$("#view-reset").addEventListener("submit", async (event) => {
  event.preventDefault();
  const submit = $("#reset-submit");
  submit.disabled = true;
  submit.textContent = "Sending…";
  try {
    await api.resetRequest($("#reset-email").value.trim());
    show($("#reset-sent"), true);
  } catch (err) {
    fail($("#reset-error"), err.message);
  } finally {
    submit.disabled = false;
    submit.textContent = "Email me a reset link";
  }
});

$("#reset-set-password").addEventListener("input", () =>
  updateMeter($("#reset-meter"), $("#reset-set-password").value),
);

$("#view-reset-set").addEventListener("submit", async (event) => {
  event.preventDefault();

  const email = $("#reset-set-email").value.trim();
  const password = $("#reset-set-password").value;
  const error = $("#reset-set-error");
  const submit = $("#reset-set-submit");
  error.hidden = true;

  if (!isEmail(email)) return fail(error, "Enter your email address.");
  if (password !== $("#reset-set-confirm").value) return fail(error, "The passwords do not match.");
  if (password.length < 12) return fail(error, "Use at least 12 characters.");

  submit.disabled = true;
  submit.textContent = "Erasing…";
  try {
    const recoveryKey = await store.resetConfirm(resetToken, email, password);
    resetToken = null;
    showKit(recoveryKey, email, () => {
      $("#signin-email").value = email;
      showAuthView("signin");
      toast("Account reset. Sign in with your new password.");
    });
  } catch (err) {
    fail(error, err.message);
  } finally {
    submit.disabled = false;
    submit.textContent = "Erase vault and start over";
  }
});

// --- the vault --------------------------------------------------------------

function enterVault() {
  pendingTotp = false;
  resumeMode = true;
  for (const id of ["#signin-password", "#signin-totp", "#signup-password", "#signup-confirm"]) {
    const node = $(id);
    if (node) node.value = "";
  }
  show($("#signin-totp-field"), false);
  show($("#signin-use-backup"), false);

  showScreen("vault");
  renderChrome();
  render();
  resetIdleTimer();
}

function lockVault(reason) {
  store.lock();
  showAuthView("signin");
  $("#auth-tagline").textContent = reason ?? "Locked. Enter your master password to unlock.";
  $("#signin-error").hidden = true;
  focus($("#signin-password"));
}

/** The plan badge and the "confirm your email" nudge. */
function renderChrome() {
  const badge = $("#plan-badge");
  badge.textContent = vault.plan === "pro" ? "Pro" : "Free";
  badge.dataset.plan = vault.plan;
  show(badge, true);

  const banner = $("#banner");
  if (!vault.emailVerified) {
    banner.replaceChildren(
      el("span", { text: "Confirm your email address to keep your vault fully active." }),
      el("button", {
        class: "mini",
        type: "button",
        text: "Resend email",
        onClick: guard(async () => {
          await api.resendVerification();
          toast("Confirmation email sent");
        }),
      }),
    );
    show(banner, true);
  } else if (vault.planStatus === "past_due") {
    banner.replaceChildren(
      el("span", {
        text: isNative
          ? "Your last payment failed."
          : "Your last payment failed. Update your card to stay on Pro.",
      }),
      el("button", {
        class: "mini",
        type: "button",
        text: "Manage billing",
        onClick: guard(async () => {
          location.href = (await api.portal()).url;
        }),
      }),
    );
    // Payments are handled on the website, and the apps do not link to them.
    if (isNative) banner.lastElementChild.remove();
    show(banner, true);
  } else {
    show(banner, false);
  }
}

store.onChange(() => {
  if (vault.locked) return;
  renderChrome();
  render();
});

// --- toolbar ----------------------------------------------------------------

$("#search").addEventListener("input", (event) => {
  view.query = event.target.value;
  render();
});

$("#btn-new").addEventListener("click", () => openEditor(null));
$("#btn-generate").addEventListener("click", () => openGenerator(null));
$("#btn-settings").addEventListener("click", () => openSettings());
$("#btn-lock").addEventListener("click", () => lockVault("Locked."));

$("#nav-toggle").addEventListener("click", () => {
  const sidebar = $("#sidebar");
  sidebar.dataset.open = sidebar.dataset.open === "true" ? "false" : "true";
});

document.addEventListener("keydown", (event) => {
  if (vault.locked) return;
  const meta = event.metaKey || event.ctrlKey;

  if (meta && event.key.toLowerCase() === "k") {
    event.preventDefault();
    $("#search").focus();
    $("#search").select();
  } else if (meta && event.key.toLowerCase() === "l") {
    event.preventDefault();
    lockVault("Locked.");
  } else if (event.key === "Escape" && document.activeElement === $("#search")) {
    $("#search").value = "";
    view.query = "";
    render();
  }
});

// --- auto-lock --------------------------------------------------------------

/**
 * An unlocked vault in an abandoned tab is the most likely way this leaks, so
 * the keys are dropped from memory after a period of inactivity. The server
 * session is deliberately left alone: unlocking again needs the master
 * password, not another round trip.
 */
let lastActivity = Date.now();
const resetIdleTimer = () => {
  lastActivity = Date.now();
};

for (const event of ["pointerdown", "keydown", "focus"]) {
  window.addEventListener(event, resetIdleTimer, { capture: true, passive: true });
}

setInterval(() => {
  if (vault.locked) return;
  if (Date.now() - lastActivity >= prefs.autoLockMinutes * 60 * 1000) {
    lockVault(`Locked after ${prefs.autoLockMinutes} minutes of inactivity.`);
  }
}, 5000);

// Closing or reloading the tab should not leave keys sitting in a bfcache entry.
window.addEventListener("pagehide", () => store.lock());

start().catch((error) => {
  console.error(error);
  toast("KalmPass failed to start.", "bad");
});
