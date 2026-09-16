/**
 * Save-on-submit.
 *
 * This only runs once somebody has switched on "Offer to save logins" and
 * granted the extension access to sites. Until then no KalmPass code runs on
 * any page at all.
 *
 * It watches for a login being sent, and when one is, it passes the username
 * and password to the background worker, which decides whether it is new,
 * changed or already saved. It reads nothing else from the page, stores
 * nothing, and shows nothing: the offer appears in the toolbar popup, where a
 * page cannot draw a lookalike of it.
 *
 * It is a plain script rather than a module, because content scripts cannot
 * be modules in every browser.
 */

(() => {
  if (globalThis.__kalmpassCapture) return;
  globalThis.__kalmpassCapture = true;

  const USERNAME_FIELDS =
    'input[type="email"], input[type="text"], input[type="tel"], input:not([type])';

  const visible = (node) => {
    const rect = node.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0 && getComputedStyle(node).visibility !== "hidden";
  };

  /**
   * Picks the password that is being set or used.
   *
   * One box is a login. Two matching boxes are a sign-up. A change of password
   * form asks for the current one first and the new one after it. In every
   * case the last filled box holds the password worth keeping.
   */
  function pickPassword(fields) {
    const values = fields.map((field) => field.value).filter(Boolean);
    return values.length ? values[values.length - 1] : "";
  }

  /**
   * The filled-in text box nearest before the first password box, and in the
   * same form as it, so a search box or a second form elsewhere on the page is
   * never mistaken for the account name.
   */
  function pickUsername(scope, firstPassword) {
    const sameForm = (field) =>
      field.form === firstPassword.form &&
      field.compareDocumentPosition(firstPassword) & Node.DOCUMENT_POSITION_FOLLOWING;

    const preferred = [...scope.querySelectorAll('input[autocomplete~="username"]')].find(
      (field) => field.value && sameForm(field),
    );
    if (preferred) return preferred.value.trim();

    const before = [...scope.querySelectorAll(USERNAME_FIELDS)].filter(
      (field) => field.value && visible(field) && sameForm(field),
    );
    return before.length ? before[before.length - 1].value.trim() : "";
  }

  let lastSent = "";

  function capture(scope) {
    const inForm = scope instanceof HTMLFormElement;
    // Outside a form, only boxes that are not in one: a form sends its own
    // submit, and should not be swept up by a click somewhere else.
    const fields = [...scope.querySelectorAll('input[type="password"]')].filter(
      (field) => field.value && (inForm || !field.form),
    );
    if (fields.length === 0) return;

    const password = pickPassword(fields);
    const username = pickUsername(scope, fields[0]);
    if (!password) return;

    // A click, an Enter and a submit often arrive for the same login.
    const fingerprint = JSON.stringify([username, password]);
    if (fingerprint === lastSent) return;
    lastSent = fingerprint;

    chrome.runtime.sendMessage({ type: "captured", username, password }).catch(() => {
      // The extension may have been updated or disabled since the page loaded.
    });
  }

  /**
   * The form around a control, or failing that the nearest element around it
   * that holds a password box, which is how most script-driven logins are laid
   * out.
   */
  function scopeOf(node) {
    const form = node.closest("form");
    if (form) return form;
    for (let el = node.parentElement; el; el = el.parentElement) {
      if (el.querySelector('input[type="password"]')) return el;
    }
    return null;
  }

  const captureAround = (node) => {
    const scope = scopeOf(node);
    if (scope) capture(scope);
  };

  document.addEventListener(
    "submit",
    (event) => {
      if (event.target instanceof HTMLFormElement) capture(event.target);
    },
    true,
  );

  // Many sites never submit a form: a script reads the boxes when a button is
  // pressed. So a press of anything button-like near a filled password counts.
  document.addEventListener(
    "click",
    (event) => {
      const target = event.target instanceof Element ? event.target : null;
      const control = target?.closest('button, input[type="submit"], [role="button"]');
      if (control) captureAround(control);
    },
    true,
  );

  document.addEventListener(
    "keydown",
    (event) => {
      if (event.key !== "Enter") return;
      const target = event.target;
      if (target instanceof HTMLInputElement) captureAround(target);
    },
    true,
  );
})();
