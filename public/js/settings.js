/** The settings dialog: security, recovery, plan, health, backups, devices. */

import { api } from "./api.js";
import { el, relativeTime } from "./dom.js";
import { crackTime, estimateStrength, generatePassphrase } from "./generator.js";
import { analyse, breachCheck } from "./health.js";
import * as store from "./store.js";
import { vault } from "./store.js";
import {
  askMasterPassword,
  busy,
  clipboard,
  confirmDialog,
  copy,
  guard,
  openModal,
  toast,
} from "./ui.js";
import { render, updateMeter, view } from "./vault-view.js";

/**
 * Preferences, not secrets. These two numbers are the only thing KalmPass ever
 * writes to disk, no vault data goes near localStorage.
 */
export const prefs = {
  autoLockMinutes: 15,
  clipboardSeconds: 45,

  load() {
    try {
      const saved = JSON.parse(localStorage.getItem("kalmpass.prefs") ?? "{}");
      if (Number.isFinite(saved.autoLockMinutes)) this.autoLockMinutes = saved.autoLockMinutes;
      if (Number.isFinite(saved.clipboardSeconds)) this.clipboardSeconds = saved.clipboardSeconds;
    } catch {
      /* A browser with storage blocked simply gets the defaults. */
    }
    clipboard.clearAfterSeconds = this.clipboardSeconds;
  },

  save() {
    clipboard.clearAfterSeconds = this.clipboardSeconds;
    try {
      localStorage.setItem(
        "kalmpass.prefs",
        JSON.stringify({
          autoLockMinutes: this.autoLockMinutes,
          clipboardSeconds: this.clipboardSeconds,
        }),
      );
    } catch {
      /* Non-fatal: the setting just will not survive a reload. */
    }
  },
};

const TABS = [
  ["security", "Security"],
  ["recovery", "Recovery Key"],
  ["plan", "Plan"],
  ["health", "Vault health"],
  ["backup", "Backup"],
  ["devices", "Devices"],
  ["about", "About"],
];

export function openSettings(initialTab = "security") {
  return openModal({
    title: "Settings",
    width: "min(660px, calc(100vw - 32px))",
    render: (close) => {
      const panel = el("div", { class: "stack" });

      const show = (id) => {
        for (const node of tabs.children) {
          node.setAttribute("aria-selected", String(node.dataset.tab === id));
        }
        panel.replaceChildren(...[PANELS[id]({ close, refresh: () => show(id) })].flat());
      };

      const tabs = el(
        "div",
        { class: "tabs", style: "margin:0 0 4px" },
        TABS.map(([id, label]) =>
          el("button", {
            class: "tab",
            type: "button",
            text: label,
            dataset: { tab: id },
            onClick: () => show(id),
          }),
        ),
      );

      show(initialTab);
      return { body: [tabs, panel] };
    },
  });
}

const section = (title, children, description) =>
  el("div", { class: "finding" }, [
    el("h3", { text: title }),
    description ? el("p", { class: "faint", style: "margin:0", text: description }) : null,
    ...children,
  ]);

const goToItem = (item) => {
  view.selectedId = item.id;
  view.filter = "all";
  render();
  document.querySelector("#modal")?.close();
};

const itemLink = (item) =>
  el("button", {
    class: "link",
    type: "button",
    style: "justify-self:start;text-align:left",
    text: item.name || "Untitled",
    onClick: () => goToItem(item),
  });

// ---------------------------------------------------------------------------

const PANELS = {
  security: ({ refresh }) => [
    section(
      "Master password",
      [
        el("button", {
          class: "ghost",
          type: "button",
          text: "Change master password",
          onClick: () => changeMasterPassword(),
        }),
      ],
      "Changing it re-wraps your vault key and signs out every other device. Your items are not re-encrypted, and your Recovery Key keeps working.",
    ),

    section(
      vault.totpEnabled ? "Two-factor authentication is on" : "Two-factor authentication is off",
      [
        el("button", {
          class: vault.totpEnabled ? "ghost" : "primary",
          type: "button",
          text: vault.totpEnabled ? "Turn off" : "Set up",
          onClick: () => (vault.totpEnabled ? disableTotp(refresh) : enableTotp(refresh)),
        }),
      ],
      vault.totpEnabled
        ? "Signing in needs a code from your authenticator app as well as your master password."
        : "Adds a second factor to signing in, so a stolen master password is not enough on its own.",
    ),

    section(
      "Auto-lock",
      [
        numberRow(
          "Lock the vault after",
          prefs.autoLockMinutes,
          "minutes idle",
          (value) => {
            prefs.autoLockMinutes = value;
            prefs.save();
          },
          { min: 1, max: 240 },
        ),
        numberRow(
          "Clear copied passwords after",
          prefs.clipboardSeconds,
          "seconds",
          (value) => {
            prefs.clipboardSeconds = value;
            prefs.save();
          },
          { min: 0, max: 300 },
        ),
      ],
      "Locking discards the keys from memory; unlocking asks for your master password again.",
    ),
  ],

  recovery: ({ refresh }) => [
    section(
      "Your Recovery Key",
      [
        el("p", { class: "faint", style: "margin:0" }, [
          vault.recoveryCreatedAt
            ? `Issued ${relativeTime(vault.recoveryCreatedAt)}.`
            : "Issued when you created your account.",
        ]),
        el("button", {
          class: "ghost",
          type: "button",
          text: "Issue a new Recovery Key",
          onClick: () => rotateRecoveryKey(refresh),
        }),
      ],
      "The only way back into your vault if you forget your master password. We do not hold a copy. If you have lost yours, issue a new one now while you can still sign in.",
    ),

    section("How recovery works", [
      el("ul", { style: "margin:0;padding-left:18px;font-size:13.5px;line-height:1.7" }, [
        el("li", { text: "Your vault key is wrapped twice: once by your master password, once by your Recovery Key." }),
        el("li", { text: "Either one opens the vault. We hold neither, so we cannot open it and neither can anyone who breaches us." }),
        el("li", { text: "Using the Recovery Key issues a fresh one, because the old one has been typed into a browser." }),
        el("li", { text: "Lose both and the data is unrecoverable by anyone. That is the trade for nobody else being able to read it." }),
      ]),
    ]),
  ],

  plan: ({ refresh }) => [planPanel(refresh)],
  health: () => [healthPanel()],

  backup: () => [
    section(
      "Export an encrypted backup",
      [
        el("button", {
          class: "primary",
          type: "button",
          text: "Export vault",
          onClick: () => exportBackup(),
        }),
      ],
      "Downloads every item encrypted under a passphrase you choose now. Unlike the live vault it survives losing your account entirely, so keep one.",
    ),
    section(
      "Restore or import",
      [
        el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, [
          el("button", {
            class: "ghost",
            type: "button",
            text: "Restore a KalmPass backup",
            onClick: () => importBackup(),
          }),
          el("button", {
            class: "ghost",
            type: "button",
            text: "Import a CSV",
            onClick: () => importCsv(),
          }),
        ]),
      ],
      "CSV exports from LastPass, Bitwarden, 1Password and Chrome are all understood. Imported items are added alongside what you already have.",
    ),
  ],

  devices: ({ refresh }) => [devicesPanel(refresh), activityPanel()],

  about: () => [
    section("Account", [
      el("p", { class: "faint", style: "margin:0" }, [
        `${vault.email} · ${vault.itemCount} items · ${vault.kdfIterations.toLocaleString()} KDF rounds` +
          `${vault.emailVerified ? "" : " · email not yet confirmed"}`,
      ]),
      vault.emailVerified
        ? null
        : el("button", {
            class: "ghost",
            type: "button",
            text: "Resend confirmation email",
            onClick: guard(async () => {
              await api.resendVerification();
              toast("Confirmation email sent");
            }),
          }),
    ]),

    section("How your vault is protected", [
      el("ul", { style: "margin:0;padding-left:18px;font-size:13.5px;line-height:1.7" }, [
        el("li", { text: "Items are encrypted with AES-256-GCM in this browser, before anything is sent." }),
        el("li", { text: "The key comes from your master password via one million rounds of PBKDF2-SHA256." }),
        el("li", { text: "Your master password is never transmitted, and the server holds no key that can decrypt an item." }),
        el("li", { text: "Everything stored in the database is encrypted a second time by the server, under a key held outside it." }),
        el("li", { text: "There is no password reset, because there is no way for anyone but you to recover the data." }),
      ]),
      el("a", { href: "/security/", class: "link", text: "Read the full security page", target: "_blank", rel: "noopener" }),
    ]),

    section(
      "Delete this account",
      [
        el("button", {
          class: "danger",
          type: "button",
          text: "Delete account permanently",
          onClick: () => deleteVault(),
        }),
      ],
      "Removes every item and the account itself. There is no undo and no backup on our side.",
    ),
  ],
};

function numberRow(label, value, suffix, onChange, { min, max }) {
  return el("div", { class: "opt" }, [
    el("span", { text: label }),
    el("input", {
      type: "number",
      value,
      min,
      max,
      style: "width:84px",
      onChange: (event) => {
        const next = Math.max(min, Math.min(max, Number(event.target.value) || min));
        event.target.value = next;
        onChange(next);
      },
    }),
    el("span", { class: "faint", text: suffix }),
  ]);
}

// --- master password --------------------------------------------------------

function changeMasterPassword() {
  return openModal({
    title: "Change master password",
    render: (close) => {
      const current = el("input", { type: "password", autocomplete: "current-password" });
      const next = el("input", { type: "password", autocomplete: "new-password" });
      const confirm = el("input", { type: "password", autocomplete: "new-password" });
      const error = el("p", { class: "error", hidden: true });
      const meter = el("div", { class: "meter" }, [
        el("div", { class: "meter-bar" }, [el("span")]),
        el("p", { class: "meter-text muted" }),
      ]);
      next.addEventListener("input", () => updateMeter(meter, next.value));

      const save = el("button", { class: "primary", type: "button", text: "Change it" });
      save.addEventListener(
        "click",
        guard(async () => {
          error.hidden = true;
          if (next.value !== confirm.value) {
            error.textContent = "The new passwords do not match.";
            error.hidden = false;
            return;
          }
          if (estimateStrength(next.value).score < 2) {
            error.textContent = "Choose something stronger. This one would not last long.";
            error.hidden = false;
            return;
          }

          const done = busy(save, "Changing…");
          try {
            await store.changeMasterPassword(current.value, next.value);
            close(true);
            toast("Master password changed. Other devices have been signed out.");
          } catch (err) {
            error.textContent = err.message;
            error.hidden = false;
            done();
          }
        }),
      );

      return {
        body: [
          el("div", { class: "warn" }, [
            el("strong", { text: "Write the new one down first." }),
            "Nobody can reset it for you. Your Recovery Key is unaffected and still works.",
          ]),
          el("label", { class: "field" }, [el("span", { text: "Current master password" }), current]),
          el("label", { class: "field" }, [el("span", { text: "New master password" }), next, meter]),
          el("label", { class: "field" }, [el("span", { text: "Confirm new password" }), confirm]),
          error,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(false) }),
          save,
        ],
      };
    },
  });
}

// --- recovery key -----------------------------------------------------------

async function rotateRecoveryKey(refresh) {
  const sure = await confirmDialog({
    title: "Issue a new Recovery Key?",
    message:
      "Your current Recovery Key will stop working immediately. Make sure you can save the new one before continuing.",
    confirmLabel: "Continue",
  });
  if (!sure) return;

  const password = await askMasterPassword({
    title: "Confirm with your master password",
    message: "This proves it is you before we replace the key.",
    confirmLabel: "Issue new key",
  });
  if (!password) return;

  await guard(async () => {
    const recoveryKey = await store.rotateRecoveryKey(password);
    showRecoveryKey(recoveryKey);
    refresh();
  })();
}

function showRecoveryKey(recoveryKey) {
  return openModal({
    title: "Your new Recovery Key",
    render: (close) => ({
      body: [
        el("div", { class: "warn" }, [
          el("strong", { text: "This is the only time you will see this." }),
          "Save it somewhere safe and offline. Your previous Recovery Key no longer works.",
        ]),
        el("div", { class: "readout kit-key", text: recoveryKey }),
        el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, [
          el("button", {
            class: "mini",
            type: "button",
            text: "Copy",
            onClick: () => copy(recoveryKey, "Recovery Key copied"),
          }),
          el("button", {
            class: "mini",
            type: "button",
            text: "Download Emergency Kit",
            onClick: () =>
              download(
                "kalmpass-emergency-kit.txt",
                [
                  "KalmPass Emergency Kit",
                  "======================",
                  "",
                  `Account:      ${vault.email}`,
                  `Recovery Key: ${recoveryKey}`,
                  `Issued:       ${new Date().toISOString()}`,
                  "",
                  "If you forget your master password, this key is the only way back",
                  "into your vault. Go to https://kalmpass.net/app/ and choose",
                  '"Forgot your master password?".',
                  "",
                  "Keep this safe and offline. Do not store it in the vault it protects.",
                  "KalmPass cannot read your vault and will never ask you for this key.",
                  "",
                ].join("\n"),
                "text/plain",
              ),
          }),
        ]),
      ],
      footer: [
        el("button", { class: "primary", type: "button", text: "I have saved it", onClick: () => close(true) }),
      ],
    }),
  });
}

// --- two-factor -------------------------------------------------------------

async function enableTotp(refresh) {
  const enrolment = await guard(() => api.totpStart())();
  if (!enrolment) return;

  const grouped = enrolment.secret.replace(/(.{4})/g, "$1 ").trim();

  await openModal({
    title: "Set up two-factor authentication",
    render: (close) => {
      const code = el("input", { type: "text", inputmode: "numeric", maxlength: 6, placeholder: "000000" });
      const error = el("p", { class: "error", hidden: true });

      const confirm = el("button", { class: "primary", type: "button", text: "Turn it on" });
      confirm.addEventListener(
        "click",
        guard(async () => {
          const done = busy(confirm, "Checking…");
          try {
            const { backupCodes } = await api.totpEnable(code.value.trim());
            vault.totpEnabled = true;
            close(true);
            showBackupCodes(backupCodes);
            refresh();
          } catch (err) {
            error.textContent = err.message;
            error.hidden = false;
            done();
          }
        }),
      );

      return {
        body: [
          el("p", { class: "muted", style: "margin:0" }, [
            "Add this key to your authenticator app, then enter the code it shows to confirm.",
          ]),
          el("div", { class: "readout", style: "letter-spacing:.08em", text: grouped }),
          el("div", { style: "display:flex;gap:8px;flex-wrap:wrap" }, [
            el("button", {
              class: "mini",
              type: "button",
              text: "Copy key",
              onClick: () => copy(enrolment.secret, "Setup key copied"),
            }),
            el("a", {
              class: "mini",
              href: enrolment.uri,
              text: "Open in authenticator app",
              style: "text-decoration:none;display:inline-block",
            }),
          ]),
          el("label", { class: "field" }, [el("span", { text: "Code from your app" }), code]),
          error,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(false) }),
          confirm,
        ],
      };
    },
  });
}

function showBackupCodes(codes) {
  return openModal({
    title: "Save your backup codes",
    render: (close) => ({
      body: [
        el("div", { class: "warn" }, [
          el("strong", { text: "This is the only time you will see these." }),
          "Each one signs you in once if you lose your authenticator. They are not a substitute for your Recovery Key. Keep both.",
        ]),
        el("div", { class: "codes" }, codes.map((code) => el("span", { text: code }))),
        el("div", { style: "display:flex;gap:8px" }, [
          el("button", {
            class: "mini",
            type: "button",
            text: "Copy all",
            onClick: () => copy(codes.join("\n"), "Backup codes copied"),
          }),
          el("button", {
            class: "mini",
            type: "button",
            text: "Download",
            onClick: () =>
              download(
                "kalmpass-backup-codes.txt",
                `KalmPass backup codes for ${vault.email}\nGenerated ${new Date().toISOString()}\n\n${codes.join("\n")}\n`,
                "text/plain",
              ),
          }),
        ]),
      ],
      footer: [
        el("button", { class: "primary", type: "button", text: "I have saved them", onClick: () => close(true) }),
      ],
    }),
  });
}

async function disableTotp(refresh) {
  const password = await askMasterPassword({
    title: "Turn off two-factor authentication",
    message: "Your master password will be the only thing protecting this account at sign-in.",
    confirmLabel: "Turn it off",
  });
  if (!password) return;

  await guard(async () => {
    await api.totpDisable(await store.authKeyFor(password));
    vault.totpEnabled = false;
    toast("Two-factor authentication turned off");
    refresh();
  })();
}

// --- plan -------------------------------------------------------------------

function planPanel(refresh) {
  const pro = vault.plan === "pro";
  const status = vault.planStatus;

  const children = [
    el("div", { class: "finding" }, [
      el("div", { class: "health-score" }, [
        el("div", { class: "plan-mark", dataset: { plan: vault.plan }, text: pro ? "Pro" : "Free" }),
        el("div", {}, [
          el("h3", { text: pro ? "You are on Pro" : "You are on the Free plan" }),
          el("p", { class: "faint", style: "margin:0" }, [
            pro
              ? status === "past_due"
                ? "Your last payment failed. Update your card to keep Pro."
                : vault.planPeriodEnd
                  ? `Renews ${new Date(vault.planPeriodEnd).toLocaleDateString()}.`
                  : "Active."
              : `${vault.itemCount} of 50 items used · 2 devices · breach monitoring not included.`,
          ]),
        ]),
      ]),
    ]),
  ];

  if (pro) {
    children.push(
      section(
        "Billing",
        [
          el("button", {
            class: "ghost",
            type: "button",
            text: "Manage subscription",
            onClick: guard(async () => {
              location.href = (await api.portal()).url;
            }),
          }),
        ],
        "Cards, invoices and cancellation are handled by Stripe. Cancelling keeps Pro until the end of the period, then drops you to Free. Nothing is ever deleted.",
      ),
    );
  } else {
    children.push(
      section(
        "Upgrade to Pro",
        [
          el("ul", { style: "margin:0;padding-left:18px;font-size:13.5px;line-height:1.7" }, [
            el("li", { text: "Unlimited items" }),
            el("li", { text: "Unlimited devices" }),
            el("li", { text: "Breach monitoring against Have I Been Pwned" }),
            el("li", { text: "Priority support" }),
          ]),
          el("button", {
            class: "primary",
            type: "button",
            text: "Upgrade",
            onClick: guard(async () => {
              const { url } = await api.checkout();
              location.href = url;
            }),
          }),
        ],
        "Encryption is identical on both plans. Pro buys capacity, not security. We are not going to sell you your own safety.",
      ),
    );
  }

  children.push(
    el("button", {
      class: "link",
      type: "button",
      text: "Refresh plan status",
      onClick: guard(async () => {
        await store.refreshAccount();
        refresh();
      }),
    }),
  );

  return el("div", { class: "stack" }, children);
}

// --- health -----------------------------------------------------------------

function healthPanel() {
  const container = el("div", { class: "stack" });
  const report = analyse(vault.items);

  container.append(
    el("div", { class: "finding" }, [
      el("div", { class: "health-score" }, [
        el("div", {
          class: "health-num",
          text: String(report.score),
          style: `color:${report.score >= 80 ? "var(--good)" : report.score >= 50 ? "var(--warn)" : "var(--bad)"}`,
        }),
        el("div", {}, [
          el("h3", { text: report.score >= 80 ? "Your vault is in good shape" : "A few things to fix" }),
          el("p", { class: "faint", style: "margin:0", text: `${report.total} items with passwords.` }),
        ]),
      ]),
    ]),
  );

  if (report.weak.length) {
    container.append(
      el("div", { class: "finding" }, [
        el("h3", {}, ["Weak passwords", el("span", { class: "pill", text: String(report.weak.length) })]),
        el(
          "ul",
          {},
          report.weak.slice(0, 12).map(({ item, strength }) =>
            el("li", {}, [itemLink(item), `: ${strength.bits} bits, cracked in ${crackTime(strength.bits)}`]),
          ),
        ),
      ]),
    );
  }

  if (report.reused.length) {
    container.append(
      el("div", { class: "finding" }, [
        el("h3", {}, ["Reused passwords", el("span", { class: "pill", text: String(report.reused.length) })]),
        el("p", { class: "faint", style: "margin:0" }, [
          "One breach at any of these sites exposes the others.",
        ]),
        el(
          "ul",
          {},
          report.reused
            .slice(0, 8)
            .map((group) => el("li", { text: group.map((item) => item.name || "Untitled").join(", ") })),
        ),
      ]),
    );
  }

  if (report.stale.length) {
    container.append(
      el("div", { class: "finding" }, [
        el("h3", {}, [
          "Not changed in over a year",
          el("span", { class: "pill", text: String(report.stale.length) }),
        ]),
        el("ul", {}, report.stale.slice(0, 10).map((item) => el("li", {}, [itemLink(item)]))),
      ]),
    );
  }

  const results = el("div");
  const button = el("button", {
    class: "ghost",
    type: "button",
    text: vault.plan === "pro" ? "Check for breaches" : "Check for breaches (Pro)",
  });

  button.addEventListener(
    "click",
    guard(async () => {
      const done = busy(button, "Checking…");
      try {
        const found = await breachCheck(vault.items, (n, total) => {
          button.textContent = `Checking ${n}/${total}…`;
        });
        results.replaceChildren(
          found.length === 0
            ? el("p", {
                class: "faint",
                style: "margin:0",
                text: "None of your passwords appear in a known breach.",
              })
            : el(
                "ul",
                {},
                found.map(({ item, count }) =>
                  el("li", {}, [itemLink(item), `: seen ${count.toLocaleString()} times. Change it.`]),
                ),
              ),
        );
      } catch (error) {
        results.replaceChildren(
          el("p", { class: "faint", style: "margin:0" }, [
            error.code === "upgrade_required"
              ? "Breach monitoring is part of Pro. "
              : `${error.message} `,
            error.code === "upgrade_required"
              ? el("button", {
                  class: "link",
                  type: "button",
                  text: "See plans",
                  onClick: () => openSettings("plan"),
                })
              : null,
          ]),
        );
      } finally {
        done();
      }
    }),
  );

  container.append(
    section(
      "Breach check",
      [button, results],
      "Sends the first five characters of each password's SHA-1 hash to Have I Been Pwned, proxied through KalmPass. The password itself never leaves this device.",
    ),
  );

  return container;
}

// --- devices and activity ---------------------------------------------------

function devicesPanel(refresh) {
  const container = el("div", { class: "stack" }, [el("p", { class: "faint", text: "Loading…" })]);

  api
    .sessions()
    .then(({ sessions }) => {
      container.replaceChildren(
        el(
          "div",
          { class: "rows" },
          sessions.map((session) =>
            el("div", { class: "entry" }, [
              el("div", { class: "entry-main" }, [
                el("div", {
                  class: "entry-label",
                  text: session.current ? "This device" : "Signed in",
                }),
                el("div", { class: "entry-value", text: shortAgent(session.label) }),
                el("div", { class: "faint", text: `Last used ${relativeTime(session.lastSeenAt)}` }),
              ]),
            ]),
          ),
        ),
        el("button", {
          class: "ghost",
          type: "button",
          text: "Sign out every other device",
          onClick: guard(async () => {
            const { revoked } = await api.revokeSessions();
            toast(
              revoked === 0
                ? "No other devices were signed in"
                : `Signed out ${revoked} device${revoked === 1 ? "" : "s"}`,
            );
            refresh();
          }),
        }),
      );
    })
    .catch(() => container.replaceChildren(el("p", { class: "error", text: "Could not load devices." })));

  return container;
}

const ACTIVITY_LABELS = {
  signup: "Account created",
  login: "Signed in",
  login_failed: "Failed sign-in attempt",
  logout: "Signed out",
  password_changed: "Master password changed",
  recovery_used: "Recovery Key used",
  recovery_key_replaced: "New Recovery Key issued",
  account_reset: "Account reset",
  email_verified: "Email confirmed",
  totp_enabled: "Two-factor turned on",
  totp_disabled: "Two-factor turned off",
  sessions_revoked: "Other devices signed out",
  plan_changed: "Plan changed",
};

function activityPanel() {
  const container = el("div", { class: "finding" }, [
    el("h3", { text: "Recent activity" }),
    el("p", { class: "faint", style: "margin:0", text: "Loading…" }),
  ]);

  api
    .activity()
    .then(({ events }) => {
      container.replaceChildren(
        el("h3", { text: "Recent activity" }),
        events.length === 0
          ? el("p", { class: "faint", style: "margin:0", text: "Nothing yet." })
          : el(
              "ul",
              {},
              events.slice(0, 25).map((event) =>
                el("li", {
                  text:
                    `${ACTIVITY_LABELS[event.kind] ?? event.kind}` +
                    `${event.detail ? `. ${event.detail}` : ""} · ${relativeTime(event.at)}`,
                }),
              ),
            ),
      );
    })
    .catch(() => {
      container.replaceChildren(
        el("h3", { text: "Recent activity" }),
        el("p", { class: "faint", style: "margin:0", text: "Could not load activity." }),
      );
    });

  return container;
}

/** User-agent strings are unreadable; reduce them to something a person can use. */
function shortAgent(agent) {
  const browser = /Edg\//.test(agent)
    ? "Edge"
    : /Chrome\//.test(agent)
      ? "Chrome"
      : /Safari\//.test(agent) && !/Chrome/.test(agent)
        ? "Safari"
        : /Firefox\//.test(agent)
          ? "Firefox"
          : "Browser";
  const platform = /Windows/.test(agent)
    ? "Windows"
    : /Android/.test(agent)
      ? "Android"
      : /iPhone|iPad/.test(agent)
        ? "iOS"
        : /Mac OS X/.test(agent)
          ? "macOS"
          : /Linux/.test(agent)
            ? "Linux"
            : "";
  return [browser, platform].filter(Boolean).join(" on ");
}

// --- backup -----------------------------------------------------------------

function exportBackup() {
  return openModal({
    title: "Export an encrypted backup",
    render: (close) => {
      const passphrase = el("input", { type: "password", autocomplete: "new-password" });
      const confirm = el("input", { type: "password", autocomplete: "new-password" });
      const error = el("p", { class: "error", hidden: true });

      const go = el("button", { class: "primary", type: "button", text: "Download backup" });
      go.addEventListener(
        "click",
        guard(async () => {
          error.hidden = true;
          if (passphrase.value !== confirm.value) {
            error.textContent = "The passphrases do not match.";
            error.hidden = false;
            return;
          }
          if (estimateStrength(passphrase.value).score < 2) {
            error.textContent = "Use a stronger passphrase. This file will sit on a disk somewhere.";
            error.hidden = false;
            return;
          }

          const done = busy(go, "Encrypting…");
          try {
            const backup = await store.exportBackup(passphrase.value);
            download(
              `kalmpass-backup-${new Date().toISOString().slice(0, 10)}.json`,
              JSON.stringify(backup, null, 2),
              "application/json",
            );
            close(true);
            toast("Backup downloaded");
          } finally {
            done();
          }
        }),
      );

      return {
        body: [
          el("p", { class: "muted", style: "margin:0" }, [
            "The file is encrypted with this passphrase, not your master password, so it stays readable even if you lose your account. Store it separately.",
          ]),
          el("label", { class: "field" }, [el("span", { text: "Backup passphrase" }), passphrase]),
          el("label", { class: "field" }, [el("span", { text: "Confirm passphrase" }), confirm]),
          el("button", {
            class: "link",
            type: "button",
            text: "Suggest a passphrase",
            onClick: () => {
              const value = generatePassphrase({ words: 6 });
              passphrase.value = value;
              confirm.value = value;
              passphrase.setAttribute("type", "text");
              confirm.setAttribute("type", "text");
            },
          }),
          error,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(false) }),
          go,
        ],
      };
    },
  });
}

function importBackup() {
  return openModal({
    title: "Restore a backup",
    render: (close) => {
      const file = el("input", { type: "file", accept: "application/json,.json" });
      const passphrase = el("input", { type: "password", autocomplete: "off" });
      const error = el("p", { class: "error", hidden: true });

      const go = el("button", { class: "primary", type: "button", text: "Restore" });
      go.addEventListener(
        "click",
        guard(async () => {
          error.hidden = true;
          if (!file.files?.[0]) {
            error.textContent = "Choose a backup file.";
            error.hidden = false;
            return;
          }

          const done = busy(go, "Restoring…");
          try {
            const count = await store.importBackup(passphrase.value, JSON.parse(await file.files[0].text()));
            close(true);
            toast(`Restored ${count} item${count === 1 ? "" : "s"}`);
            render();
          } catch (err) {
            error.textContent =
              err.name === "OperationError" || /decrypt/i.test(err.message ?? "")
                ? "That passphrase does not open this backup."
                : err.message;
            error.hidden = false;
            done();
          }
        }),
      );

      return {
        body: [
          el("label", { class: "field" }, [el("span", { text: "Backup file" }), file]),
          el("label", { class: "field" }, [el("span", { text: "Backup passphrase" }), passphrase]),
          el("p", {
            class: "faint",
            style: "margin:0",
            text: "Items are added to your vault; nothing existing is replaced.",
          }),
          error,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(false) }),
          go,
        ],
      };
    },
  });
}

function importCsv() {
  return openModal({
    title: "Import a CSV",
    render: (close) => {
      const file = el("input", { type: "file", accept: ".csv,text/csv" });
      const error = el("p", { class: "error", hidden: true });

      const go = el("button", { class: "primary", type: "button", text: "Import" });
      go.addEventListener(
        "click",
        guard(async () => {
          error.hidden = true;
          if (!file.files?.[0]) {
            error.textContent = "Choose a CSV file.";
            error.hidden = false;
            return;
          }

          const done = busy(go, "Importing…");
          try {
            const count = await store.importCsv(await file.files[0].text());
            close(true);
            toast(`Imported ${count} item${count === 1 ? "" : "s"}`);
            render();
          } catch (err) {
            error.textContent = err.message;
            error.hidden = false;
            done();
          }
        }),
      );

      return {
        body: [
          el("div", { class: "warn" }, [
            el("strong", { text: "Delete the CSV afterwards." }),
            "An unencrypted export of your passwords sitting in a downloads folder is the weakest link in this whole system.",
          ]),
          el("label", { class: "field" }, [el("span", { text: "CSV file" }), file]),
          error,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(false) }),
          go,
        ],
      };
    },
  });
}

// --- danger -----------------------------------------------------------------

async function deleteVault() {
  const sure = await confirmDialog({
    title: "Delete this account?",
    message:
      "Every item will be destroyed along with the account. We hold no copy and no backup. If you have not exported one, this is final.",
    confirmLabel: "Continue",
    danger: true,
  });
  if (!sure) return;

  const password = await askMasterPassword({
    title: "Confirm with your master password",
    message: "This cannot be undone.",
    confirmLabel: "Delete everything",
  });
  if (!password) return;

  await guard(async () => {
    await api.deleteAccount({
      currentAuthKey: await store.authKeyFor(password),
      confirm: "DELETE",
    });
    location.href = "/";
  })();
}

// --- helpers ----------------------------------------------------------------

function download(filename, content, type) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = el("a", { href: url, download: filename });
  document.body.append(link);
  link.click();
  link.remove();
  // Revoked promptly so the blob, which holds vault data. Is not left alive.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
