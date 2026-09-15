/** The vault screen: filters, list, detail panel, and the item editor. */

import { $, clear, el, focus, hostOf, relativeTime } from "./dom.js";
import { crackTime, estimateStrength, generatePassphrase, generatePassword } from "./generator.js";
import * as store from "./store.js";
import { secondsRemaining, totpCode, validateTotp } from "./totp.js";
import { avatarFor, busy, confirmDialog, copy, guard, openModal, toast } from "./ui.js";
import { vault } from "./store.js";

export const view = { filter: "all", folder: null, query: "", selectedId: null };

let ticker = null;

// --- derived state ----------------------------------------------------------

/**
 * Weak and reused flags, computed once per render rather than per row, a vault
 * of a few thousand items otherwise re-scores the same password repeatedly.
 */
function index(items) {
  const counts = new Map();
  const strengths = new Map();
  for (const item of items) {
    if (item.deletedAt || !item.password) continue;
    counts.set(item.password, (counts.get(item.password) ?? 0) + 1);
    if (!strengths.has(item.password)) strengths.set(item.password, estimateStrength(item.password));
  }
  return {
    isReused: (item) => (counts.get(item.password) ?? 0) > 1,
    isWeak: (item) => (strengths.get(item.password)?.score ?? 4) <= 1,
    strengthOf: (item) => strengths.get(item.password) ?? estimateStrength(item.password),
  };
}

function visibleItems(flags) {
  const query = view.query.trim().toLowerCase();

  let items = vault.items.filter((item) =>
    view.filter === "trash" ? item.deletedAt : !item.deletedAt,
  );

  if (view.filter === "favorites") items = items.filter((item) => item.favorite);
  if (view.filter === "weak") items = items.filter((item) => item.password && flags.isWeak(item));
  if (view.filter === "reused") items = items.filter((item) => flags.isReused(item));
  if (view.filter === "folder") items = items.filter((item) => item.folder === view.folder);

  if (query) {
    items = items.filter((item) =>
      [item.name, item.username, item.url, item.folder, item.notes]
        .filter(Boolean)
        .some((field) => field.toLowerCase().includes(query)),
    );
  }
  return items;
}

const foldersOf = (items) =>
  [...new Set(items.filter((i) => !i.deletedAt && i.folder).map((i) => i.folder))].sort();

// --- render -----------------------------------------------------------------

export function render() {
  const flags = index(vault.items);
  const items = visibleItems(flags);

  renderSidebar(flags);
  renderList(items, flags);
  renderDetail(flags);
}

function sideButton(id, label, count, extra = {}) {
  return el(
    "button",
    {
      class: "side-item",
      type: "button",
      "aria-current": String(view.filter === id && (id !== "folder" || view.folder === extra.folder)),
      onClick: () => {
        view.filter = id;
        view.folder = extra.folder ?? null;
        $("#sidebar").dataset.open = "false";
        render();
      },
    },
    [
      extra.dot ? el("span", { class: "side-dot", style: `color:${extra.dot}` }) : null,
      el("span", { text: label }),
      count === null ? null : el("span", { class: "side-count", text: String(count) }),
    ],
  );
}

function renderSidebar(flags) {
  const live = vault.items.filter((item) => !item.deletedAt);
  const nav = clear($("#sidebar"));

  nav.append(
    sideButton("all", "All items", live.length),
    sideButton("favorites", "Favorites", live.filter((i) => i.favorite).length),
  );

  const weak = live.filter((i) => i.password && flags.isWeak(i)).length;
  const reused = live.filter((i) => flags.isReused(i)).length;
  if (weak || reused) {
    nav.append(el("div", { class: "side-label", text: "Needs attention" }));
    if (weak) nav.append(sideButton("weak", "Weak", weak, { dot: "var(--bad)" }));
    if (reused) nav.append(sideButton("reused", "Reused", reused, { dot: "var(--warn)" }));
  }

  const folders = foldersOf(vault.items);
  if (folders.length) {
    nav.append(el("div", { class: "side-label", text: "Folders" }));
    for (const folder of folders) {
      nav.append(
        sideButton("folder", folder, live.filter((i) => i.folder === folder).length, { folder }),
      );
    }
  }

  nav.append(
    el("div", { class: "side-label", text: "Other" }),
    sideButton("trash", "Trash", vault.items.filter((i) => i.deletedAt).length),
  );
}

function renderList(items, flags) {
  const list = clear($("#list"));

  if (items.length === 0) {
    list.append(
      el("div", { class: "empty" }, [
        el("p", { text: emptyMessage() }),
        view.filter === "all" && !view.query
          ? el("button", {
              class: "primary",
              type: "button",
              text: "Add your first item",
              onClick: () => openEditor(null),
            })
          : null,
      ]),
    );
    return;
  }

  for (const item of items) {
    const avatar = avatarFor(item.name || hostOf(item.url));
    list.append(
      el(
        "button",
        {
          class: "row",
          type: "button",
          "aria-selected": String(item.id === view.selectedId),
          onClick: () => select(item.id),
        },
        [
          el("span", {
            class: "avatar",
            style: `background:${avatar.background}`,
            text: avatar.initials,
          }),
          el("span", { class: "row-main" }, [
            el("span", { class: "row-name", text: item.name || "Untitled" }),
            el("span", {
              class: "row-sub",
              text: item.username || hostOf(item.url) || "No username",
            }),
          ]),
          item.totp ? el("span", { class: "row-flag flag-totp", text: "2FA" }) : null,
          !item.deletedAt && item.password && flags.isWeak(item)
            ? el("span", { class: "row-flag flag-weak", text: "weak" })
            : null,
          !item.deletedAt && flags.isReused(item)
            ? el("span", { class: "row-flag flag-reused", text: "reused" })
            : null,
        ],
      ),
    );
  }
}

function emptyMessage() {
  if (view.query) return `Nothing matches “${view.query}”.`;
  return {
    trash: "The trash is empty.",
    favorites: "No favorites yet. Star an item to keep it here.",
    weak: "No weak passwords. Nicely done.",
    reused: "No reused passwords. Nicely done.",
    folder: "This folder is empty.",
    all: "Your vault is empty.",
  }[view.filter];
}

function select(id) {
  view.selectedId = id;
  $(".body").dataset.view = "detail";
  render();
}

// --- detail -----------------------------------------------------------------

function entry(label, value, actions = [], options = {}) {
  return el("div", { class: "entry" }, [
    el("div", { class: "entry-main" }, [
      el("div", { class: "entry-label", text: label }),
      options.node ?? el("div", { class: `entry-value${options.secret ? " secret" : ""}`, text: value }),
    ]),
    actions.length ? el("div", { class: "entry-actions" }, actions) : null,
  ]);
}

const miniButton = (label, onClick) =>
  el("button", { class: "mini", type: "button", text: label, onClick });

function renderDetail(flags) {
  clearInterval(ticker);
  ticker = null;

  const panel = clear($("#detail"));
  const item = vault.items.find((row) => row.id === view.selectedId);

  if (!item) {
    panel.append(
      el("div", { class: "empty" }, [el("p", { text: "Select an item to see it here." })]),
    );
    return;
  }

  const avatar = avatarFor(item.name || hostOf(item.url));
  panel.append(
    el("div", { class: "detail-head" }, [
      el("button", {
        class: "mini only-narrow",
        type: "button",
        text: "←",
        "aria-label": "Back to list",
        onClick: () => {
          $(".body").dataset.view = "list";
        },
      }),
      el("span", {
        class: "avatar",
        style: `background:${avatar.background}`,
        text: avatar.initials,
      }),
      el("div", { class: "detail-title" }, [
        el("h2", { text: item.name || "Untitled" }),
        el("p", { class: "faint", style: "margin:2px 0 0", text: folderLine(item) }),
      ]),
      item.deletedAt
        ? null
        : el("button", {
            class: "mini",
            type: "button",
            text: item.favorite ? "★ Favorite" : "☆ Favorite",
            onClick: guard(async () => {
              await store.saveItem({ ...item, favorite: !item.favorite });
              toast(item.favorite ? "Removed from favorites" : "Added to favorites");
            }),
          }),
    ]),
  );

  const rows = el("div", { class: "rows" });

  if (item.username) {
    rows.append(
      entry("Username", item.username, [
        miniButton("Copy", () => copy(item.username, "Username copied")),
      ]),
    );
  }

  if (item.password) rows.append(passwordEntry(item, flags));
  if (item.totp) rows.append(totpEntry(item));

  if (item.url) {
    rows.append(
      entry("Website", item.url, [
        miniButton("Copy", () => copy(item.url, "Address copied")),
        miniButton("Open", () => {
          // noopener/noreferrer so the opened site cannot reach back into this
          // tab or learn where the click came from.
          window.open(
            item.url.includes("://") ? item.url : `https://${item.url}`,
            "_blank",
            "noopener,noreferrer",
          );
        }),
      ]),
    );
  }

  if (item.notes) {
    rows.append(entry("Notes", item.notes, [miniButton("Copy", () => copy(item.notes, "Notes copied"))]));
  }

  panel.append(rows);

  if (item.history?.length) panel.append(historyBlock(item));

  panel.append(
    el("p", { class: "faint", style: "margin:0 0 16px" }, [
      `Updated ${relativeTime(item.updatedAt)}`,
      item.passwordUpdatedAt ? ` · password changed ${relativeTime(item.passwordUpdatedAt)}` : "",
    ]),
    detailActions(item),
  );
}

function folderLine(item) {
  const parts = [item.folder, hostOf(item.url)].filter(Boolean);
  return parts.length ? parts.join(" · ") : "No folder";
}

function passwordEntry(item, flags) {
  const strength = flags.strengthOf(item);
  let revealed = false;

  const value = el("div", { class: "entry-value secret", text: "•".repeat(12) });
  const meta = el("div", { class: "faint", style: "margin-top:4px" }, [
    `${strength.label} · ${strength.bits} bits · ${crackTime(strength.bits)} to crack`,
  ]);

  const toggle = miniButton("Reveal", () => {
    revealed = !revealed;
    value.textContent = revealed ? item.password : "•".repeat(12);
    toggle.textContent = revealed ? "Hide" : "Reveal";
  });

  return entry("Password", "", [toggle, miniButton("Copy", () => copy(item.password, "Password copied"))], {
    node: el("div", {}, [value, meta]),
  });
}

/**
 * A live authenticator code, recomputed every second along with the ring that
 * shows how long it has left.
 */
function totpEntry(item) {
  const config = validateTotp(item.totp);
  if (!config.ok || !config.config) {
    return entry("Authenticator", "This authenticator key could not be read.");
  }

  const code = el("div", { class: "totp-code", text: "······" });
  const ring = el("span", { class: "totp-ring" });
  const period = config.config.period || 30;

  const tick = async () => {
    try {
      const next = await totpCode(config.config);
      code.textContent = `${next.slice(0, 3)} ${next.slice(3)}`;
      const left = secondsRemaining(period);
      ring.style.setProperty("--progress", `${(left / period) * 360}deg`);
    } catch {
      code.textContent = "error";
    }
  };
  tick();
  ticker = setInterval(tick, 1000);

  return entry("Authenticator code", "", [
    miniButton("Copy", async () => copy(code.textContent.replace(/\s/g, ""), "Code copied")),
  ], {
    node: el("div", { style: "display:flex;align-items:center;gap:12px" }, [ring, code]),
  });
}

function historyBlock(item) {
  const list = el("div", { class: "rows" });
  for (const record of item.history) {
    list.append(
      entry(`Replaced ${relativeTime(record.changedAt)}`, "•".repeat(10), [
        miniButton("Copy", () => copy(record.password, "Previous password copied")),
      ], { secret: true }),
    );
  }
  return el("details", { style: "margin-bottom:18px" }, [
    el("summary", { class: "muted", style: "cursor:pointer;margin-bottom:10px" }, [
      `Previous passwords (${item.history.length})`,
    ]),
    list,
  ]);
}

function detailActions(item) {
  if (item.deletedAt) {
    return el("div", { class: "detail-actions" }, [
      el("button", {
        class: "primary",
        type: "button",
        text: "Restore",
        onClick: guard(async () => {
          await store.restoreItem(item.id);
          toast("Restored");
          render();
        }),
      }),
      el("button", {
        class: "danger",
        type: "button",
        text: "Delete forever",
        onClick: guard(async () => {
          const sure = await confirmDialog({
            title: "Delete forever?",
            message: `“${item.name || "Untitled"}” will be gone for good. This cannot be undone.`,
            confirmLabel: "Delete forever",
            danger: true,
          });
          if (!sure) return;
          await store.purgeItem(item.id);
          view.selectedId = null;
          toast("Deleted");
          render();
        }),
      }),
    ]);
  }

  return el("div", { class: "detail-actions" }, [
    el("button", { class: "primary", type: "button", text: "Edit", onClick: () => openEditor(item) }),
    el("button", {
      class: "ghost",
      type: "button",
      text: "Move to trash",
      onClick: guard(async () => {
        await store.deleteItem(item.id);
        view.selectedId = null;
        toast("Moved to trash");
        render();
      }),
    }),
  ]);
}

// --- editor -----------------------------------------------------------------

export function openEditor(existing) {
  const item = existing ?? {
    name: "",
    username: "",
    password: "",
    url: "",
    notes: "",
    totp: "",
    folder: "",
  };

  return openModal({
    title: existing ? "Edit item" : "New item",
    render: (close) => {
      const field = (label, node) => el("label", { class: "field" }, [el("span", { text: label }), node]);

      const name = el("input", { type: "text", value: item.name });
      const username = el("input", { type: "text", value: item.username, autocomplete: "off" });
      const password = el("input", { type: "password", value: item.password, autocomplete: "new-password" });
      const url = el("input", { type: "text", value: item.url, spellcheck: false, autocomplete: "off" });
      const folder = el("input", { type: "text", value: item.folder, list: "folders", autocomplete: "off" });
      const totp = el("input", { type: "text", value: item.totp, spellcheck: false, autocomplete: "off" });
      const notes = el("textarea", { value: item.notes });
      const error = el("p", { class: "error", hidden: true });

      const meter = el("div", { class: "meter" }, [
        el("div", { class: "meter-bar" }, [el("span")]),
        el("p", { class: "meter-text muted" }),
      ]);
      const refreshMeter = () => updateMeter(meter, password.value);
      password.addEventListener("input", refreshMeter);
      refreshMeter();

      const reveal = el("button", {
        class: "mini",
        type: "button",
        text: "Show",
        onClick: () => {
          const hidden = password.getAttribute("type") === "password";
          password.setAttribute("type", hidden ? "text" : "password");
          reveal.textContent = hidden ? "Hide" : "Show";
        },
      });

      const fill = el("button", {
        class: "mini",
        type: "button",
        text: "Generate",
        onClick: () => {
          password.value = generatePassword();
          password.setAttribute("type", "text");
          reveal.textContent = "Hide";
          refreshMeter();
        },
      });

      const datalist = el("datalist", { id: "folders" }, foldersOf(vault.items).map((f) => el("option", { value: f })));

      const save = el("button", { class: "primary", type: "button", text: "Save" });
      save.addEventListener(
        "click",
        guard(async () => {
          if (!name.value.trim() && !url.value.trim()) {
            error.textContent = "Give the item a name or a website.";
            error.hidden = false;
            return;
          }
          const check = validateTotp(totp.value);
          if (!check.ok) {
            error.textContent = check.message;
            error.hidden = false;
            return;
          }

          const done = busy(save, "Saving…");
          try {
            const saved = await store.saveItem({
              ...(existing ? { id: existing.id } : {}),
              name: name.value.trim() || hostOf(url.value),
              username: username.value.trim(),
              password: password.value,
              url: url.value.trim(),
              folder: folder.value.trim(),
              totp: totp.value.trim(),
              notes: notes.value,
            });
            view.selectedId = saved.id;
            close(saved);
            toast(existing ? "Saved" : "Item added");
            render();
          } catch (err) {
            error.textContent =
              err.code === "conflict"
                ? "This item changed on another device. Reopen it and try again."
                : err.message;
            error.hidden = false;
            done();
          }
        }),
      );

      return {
        body: [
          field("Name", name),
          el("div", { class: "grid-2" }, [field("Username", username), field("Website", url)]),
          el("label", { class: "field" }, [
            el("span", { text: "Password" }),
            el("div", { style: "display:flex;gap:6px;align-items:start" }, [
              el("div", { style: "flex:1" }, [password]),
              reveal,
              fill,
            ]),
            meter,
          ]),
          field("Folder", folder),
          el("label", { class: "field" }, [
            el("span", { text: "Authenticator key (optional)" }),
            totp,
            el("span", {
              class: "faint",
              text: "Paste the site's setup key or its otpauth:// link. Codes are generated on this device.",
            }),
          ]),
          field("Notes", notes),
          datalist,
          error,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Cancel", onClick: () => close(null) }),
          save,
        ],
      };
    },
  });
}

export function updateMeter(meter, password) {
  const strength = estimateStrength(password);
  meter.dataset.score = String(strength.score);
  meter.querySelector(".meter-bar > span").style.width = `${Math.min(100, (strength.bits / 110) * 100)}%`;
  meter.querySelector(".meter-text").textContent = password
    ? `${strength.label} · ${strength.bits} bits · ${crackTime(strength.bits)} to crack`
    : "";
}

// --- generator dialog -------------------------------------------------------

export function openGenerator(onUse) {
  return openModal({
    title: "Generate a password",
    render: (close) => {
      const state = { mode: "password", length: 20, words: 5 };
      const output = el("div", { class: "readout" });
      const note = el("p", { class: "faint", style: "margin:0" });

      const lower = el("input", { type: "checkbox", checked: true });
      const upper = el("input", { type: "checkbox", checked: true });
      const digits = el("input", { type: "checkbox", checked: true });
      const symbols = el("input", { type: "checkbox", checked: true });
      const ambiguous = el("input", { type: "checkbox" });

      const lengthInput = el("input", { type: "range", min: 8, max: 64, value: state.length });
      const lengthLabel = el("span", { class: "faint", text: `${state.length} characters` });
      const wordsInput = el("input", { type: "range", min: 3, max: 10, value: state.words });
      const wordsLabel = el("span", { class: "faint", text: `${state.words} words` });

      const passwordOptions = el("div", { class: "opts" }, [
        el("label", { class: "opt" }, [lengthInput]),
        lengthLabel,
        el("label", { class: "opt" }, [lower, "Lowercase a-z"]),
        el("label", { class: "opt" }, [upper, "Uppercase A-Z"]),
        el("label", { class: "opt" }, [digits, "Digits 0-9"]),
        el("label", { class: "opt" }, [symbols, "Symbols !#$%"]),
        el("label", { class: "opt" }, [ambiguous, "Avoid lookalike characters"]),
      ]);

      const passphraseOptions = el("div", { class: "opts", hidden: true }, [
        el("label", { class: "opt" }, [wordsInput]),
        wordsLabel,
      ]);

      const regenerate = () => {
        const value =
          state.mode === "password"
            ? generatePassword({
                length: Number(lengthInput.value),
                lower: lower.checked,
                upper: upper.checked,
                digits: digits.checked,
                symbols: symbols.checked,
                avoidAmbiguous: ambiguous.checked,
              })
            : generatePassphrase({ words: Number(wordsInput.value) });

        output.textContent = value;
        const strength = estimateStrength(value);
        note.textContent = `${strength.bits} bits · ${crackTime(strength.bits)} for an offline attacker`;
        lengthLabel.textContent = `${lengthInput.value} characters`;
        wordsLabel.textContent = `${wordsInput.value} words`;
      };

      for (const control of [lower, upper, digits, symbols, ambiguous, lengthInput, wordsInput]) {
        control.addEventListener("input", regenerate);
      }

      const tab = (id, label) =>
        el("button", {
          class: "tab",
          type: "button",
          text: label,
          "aria-selected": String(state.mode === id),
          onClick: (event) => {
            state.mode = id;
            for (const node of event.target.parentElement.children) {
              node.setAttribute("aria-selected", String(node === event.target));
            }
            passwordOptions.hidden = id !== "password";
            passphraseOptions.hidden = id !== "passphrase";
            regenerate();
          },
        });

      regenerate();

      return {
        body: [
          el("div", { class: "tabs", style: "margin:0" }, [
            tab("password", "Password"),
            tab("passphrase", "Passphrase"),
          ]),
          output,
          note,
          passwordOptions,
          passphraseOptions,
        ],
        footer: [
          el("button", { class: "ghost", type: "button", text: "Regenerate", onClick: regenerate }),
          el("button", {
            class: "ghost",
            type: "button",
            text: "Copy",
            onClick: () => copy(output.textContent, "Password copied"),
          }),
          onUse
            ? el("button", {
                class: "primary",
                type: "button",
                text: "Use it",
                onClick: () => {
                  onUse(output.textContent);
                  close(output.textContent);
                },
              })
            : el("button", { class: "primary", type: "button", text: "Done", onClick: () => close(null) }),
        ],
      };
    },
  });
}

export { focus };
