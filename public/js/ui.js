/** Toasts, modals, and the clipboard, the shared furniture. */

import { $, clear, el, focus } from "./dom.js";

const toasts = () => $("#toasts");
const dialog = () => $("#modal");

export function toast(message, kind = "ok") {
  const node = el("div", { class: "toast", dataset: { kind }, text: message });
  toasts().append(node);
  setTimeout(() => {
    node.classList.add("is-leaving");
    setTimeout(() => node.remove(), 220);
  }, kind === "bad" ? 4200 : 2400);
}

// --- clipboard --------------------------------------------------------------

/** Seconds before a copied secret is wiped from the clipboard. 0 disables it. */
export const clipboard = { clearAfterSeconds: 45 };

let clearTimer = null;

/**
 * Copies, then overwrites the clipboard a little later.
 *
 * A password sitting in the clipboard is readable by anything else on the
 * machine and by the OS clipboard history, so it should not sit there.
 */
export async function copy(text, label = "Copied") {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    toast("Your browser blocked the clipboard.", "bad");
    return false;
  }

  const seconds = clipboard.clearAfterSeconds;
  toast(seconds > 0 ? `${label}. Clears in ${seconds}s` : label);

  clearTimeout(clearTimer);
  if (seconds > 0) {
    clearTimer = setTimeout(async () => {
      try {
        // Only wipe if this tab is still in play; otherwise the user has almost
        // certainly copied something of their own since.
        if (document.hasFocus()) await navigator.clipboard.writeText("");
      } catch {
        /* Nothing to do, the clipboard is a courtesy, not a guarantee. */
      }
    }, seconds * 1000);
  }
  return true;
}

// --- modal ------------------------------------------------------------------

let onClose = null;

/**
 * Opens the single <dialog>. `render` receives a close function and returns the
 * body content plus optional footer buttons.
 */
export function openModal({ title, render, wide }) {
  const node = dialog();
  clear(node);
  node.classList.toggle("is-wide", Boolean(wide));

  let settle;
  const result = new Promise((resolve) => {
    settle = resolve;
  });

  const close = (value) => {
    onClose = null;
    settle(value);
    node.close();
  };
  onClose = () => settle(undefined);

  const { body, footer } = render(close);

  node.append(
    el("div", { class: "modal-head" }, [
      el("h2", { text: title }),
      el("button", {
        class: "close-x",
        type: "button",
        "aria-label": "Close",
        text: "×",
        onClick: () => close(undefined),
      }),
    ]),
    el("div", { class: "modal-body" }, body),
    footer ? el("div", { class: "modal-foot" }, footer) : null,
  );

  node.showModal();
  focus(node.querySelector("input, textarea, button:not(.close-x)"));
  return result;
}

dialog()?.addEventListener("close", () => {
  onClose?.();
  onClose = null;
});

export function closeModal() {
  dialog()?.close();
}

// --- common dialogs ---------------------------------------------------------

export function confirmDialog({ title, message, confirmLabel = "Confirm", danger = false }) {
  return openModal({
    title,
    render: (close) => ({
      body: [el("p", { class: "muted m0", text: message })],
      footer: [
        el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(false) }),
        el("button", {
          class: danger ? "danger" : "primary",
          type: "button",
          text: confirmLabel,
          onClick: () => close(true),
        }),
      ],
    }),
  }).then((value) => value === true);
}

/**
 * Asks for the master password again.
 *
 * Used before anything that a stolen unlocked session should not be able to do
 * on its own: changing the password, turning off the second factor, deleting
 * the vault.
 */
export function askMasterPassword({ title, message, confirmLabel = "Continue" }) {
  return openModal({
    title,
    render: (close) => {
      const input = el("input", { type: "password", autocomplete: "current-password" });
      const error = el("p", { class: "error", hidden: true });

      const submit = () => {
        if (!input.value) {
          error.textContent = "Enter your master password.";
          error.hidden = false;
          return;
        }
        close(input.value);
      };

      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          submit();
        }
      });

      return {
        body: [
          message ? el("p", { class: "muted m0", text: message }) : null,
          el("label", { class: "field" }, [el("span", { text: "Master password" }), input]),
          error,
        ],
        footer: [
          el("button", {
            class: "ghost",
            type: "button",
            text: "Cancel",
            onClick: () => close(null),
          }),
          el("button", { class: "primary", type: "button", text: confirmLabel, onClick: submit }),
        ],
      };
    },
  }).then((value) => value ?? null);
}

// --- misc -------------------------------------------------------------------

/** A stable colour per item, so the vault list is scannable by shape and hue. */
export function avatarFor(name) {
  const text = (name || "?").trim();
  let hash = 0;
  for (let i = 0; i < text.length; i++) hash = (hash * 31 + text.charCodeAt(i)) >>> 0;
  const hue = hash % 12;
  const initials = text
    .split(/[\s._-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0])
    .join("");
  // An index into the fixed set of gradients in app.css. A generated colour
  // would have to travel as an inline style, which the CSP forbids.
  return { initials: initials || "?", hue: String(hue) };
}

/** Wraps an async handler so a thrown error becomes a toast, not a dead button. */
export function guard(handler) {
  return async (...args) => {
    try {
      return await handler(...args);
    } catch (error) {
      toast(error?.message ?? "Something went wrong.", "bad");
      return undefined;
    }
  };
}

export function busy(button, label = "Working…") {
  const original = button.textContent;
  button.disabled = true;
  button.textContent = label;
  return () => {
    button.disabled = false;
    button.textContent = original;
  };
}
