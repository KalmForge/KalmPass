/**
 * The operator dashboard.
 *
 * Everything here is counts, plans and dates. There is no view of vault
 * contents, because the server cannot produce one.
 *
 * Note that nothing sets an inline style. The Content-Security-Policy forbids
 * style attributes, so anything that varies at runtime rides on a class or, in
 * the chart, on an SVG presentation attribute.
 */

import { $, clear, el, relativeTime } from "./dom.js";

const SVG_NS = "http://www.w3.org/2000/svg";
const main = () => $("#main");

// --- entry ------------------------------------------------------------------

boot();

async function boot() {
  let response;
  try {
    response = await fetch("/api/admin/overview", {
      credentials: "same-origin",
      cache: "no-store",
    });
  } catch {
    // Only a genuine network failure reaches here. A rendering bug must not be
    // reported as one, which is why the fetch is caught on its own.
    showMessage("Could not reach the server.", "Check your connection and reload.", "/");
    return;
  }

  if (response.status === 401) {
    showMessage("Sign in first.", "Open the vault, unlock it, then come back here.", "/app/");
    return;
  }
  if (response.status === 404) {
    // The API answers 404 rather than 403 for a non-admin, so it never confirms
    // to a stranger that the endpoint exists.
    showMessage("Not available.", "This is not the admin account for this instance.", "/app/");
    return;
  }
  if (!response.ok) {
    showMessage("Something went wrong.", `The server answered ${response.status}.`, "/app/");
    return;
  }

  try {
    render(await response.json());
  } catch (error) {
    console.error(error);
    showMessage("This page failed to render.", String(error?.message ?? error), "/app/");
  }
}

function showMessage(title, detail, href) {
  clear(main()).append(
    el("div", { class: "admin-head" }, [el("h1", { text: title })]),
    el("p", { class: "soft", text: detail }),
    el("p", { class: "mt-22" }, [el("a", { class: "btn btn-line", href, text: "Go back" })]),
  );
}

// --- render -----------------------------------------------------------------

function render(data) {
  const t = data.totals;
  const money = new Intl.NumberFormat("en-GB", {
    style: "currency",
    currency: data.currency,
    maximumFractionDigits: 0,
  });

  clear(main()).append(
    el("div", { class: "admin-head" }, [
      el("h1", { text: "Overview" }),
      el("span", { class: "faint", text: `Generated ${relativeTime(data.generatedAt)}` }),
    ]),

    tiles([
      ["Accounts", t.accounts, `${t.verified} confirmed`],
      ["Paying", t.pro, t.accounts ? `${percent(t.pro, t.accounts)} of accounts` : ""],
      ["Price", money.format(data.price), `per ${data.interval}`],
      ["Monthly revenue", money.format(t.mrr), `${money.format(data.arr)} a year`],
      ["New", t.newInWindow, `in ${data.windowDays} days`],
      ["Active", t.activeInWindow, `in ${data.windowDays} days`],
      [
        "Items stored",
        t.itemsLive,
        t.itemsTotal > t.itemsLive ? `${t.itemsTotal - t.itemsLive} in trash` : "",
      ],
      ["Live sessions", t.liveSessions, ""],
      [
        "Payment failed",
        t.pastDue,
        t.pastDue > 0 ? "needs chasing" : "none",
        t.pastDue > 0 ? "attention" : null,
      ],
      [
        "Locked out",
        t.lockedOut,
        t.lockedOut > 0 ? "too many attempts" : "none",
        t.lockedOut > 0 ? "attention" : null,
      ],
    ]),

    el("section", { class: "panel" }, [
      el("h2", { text: "Signups" }),
      el("p", {
        class: "sub",
        text: `New accounts per day over the last ${data.windowDays} days.`,
      }),
      signupChart(data.signups),
    ]),

    el("section", { class: "panel" }, [
      el("h2", { text: "Accounts" }),
      el("p", {
        class: "sub",
        text: "Newest first. KalmPass cannot show what any of these vaults hold, only how many items are in them.",
      }),
      accountsTable(data.accounts),
      el("p", {
        class: "note-line",
        text:
          data.accounts.length >= 100
            ? "Showing the 100 most recent accounts."
            : `${data.accounts.length} account${data.accounts.length === 1 ? "" : "s"}.`,
      }),
    ]),
  );
}

const percent = (part, whole) => `${Math.round((part / whole) * 100)}%`;

function tiles(rows) {
  return el(
    "dl",
    { class: "tiles" },
    rows.map(([label, value, detail, state]) =>
      el("div", { class: "tile", dataset: state ? { state } : {} }, [
        el("dt", { text: label }),
        el("dd", {}, [
          typeof value === "number" ? value.toLocaleString() : String(value),
          detail ? el("small", { text: detail }) : null,
        ]),
      ]),
    ),
  );
}

// --- chart ------------------------------------------------------------------

function svgEl(tag, attrs = {}) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [key, value] of Object.entries(attrs)) node.setAttribute(key, String(value));
  return node;
}

/**
 * One series over time, so a bar chart in a single hue with no legend. The
 * heading names the series, which is all the identity one series needs.
 *
 * Every day in the window is drawn, zeroes included, so a quiet fortnight looks
 * quiet rather than being compressed away.
 */
function signupChart(series) {
  const W = 960;
  const H = 230;
  const PAD = { top: 14, right: 8, bottom: 28, left: 34 };

  const plotW = W - PAD.left - PAD.right;
  const plotH = H - PAD.top - PAD.bottom;
  const peak = Math.max(1, ...series.map((d) => d.count));
  const total = series.reduce((n, d) => n + d.count, 0);

  // A round ceiling keeps the gridline labels whole numbers.
  const ceiling = peak <= 4 ? 4 : Math.ceil(peak / 5) * 5;
  const step = plotW / series.length;
  // Two pixels of paper between neighbours, so bars read as separate marks.
  const barW = Math.max(2, step - 2);
  const y = (value) => PAD.top + plotH - (value / ceiling) * plotH;

  const svg = svgEl("svg", {
    viewBox: `0 0 ${W} ${H}`,
    role: "img",
    "aria-label": `New accounts per day. ${total} in total, peaking at ${peak} in one day.`,
  });

  for (let i = 0; i <= 4; i++) {
    const value = (ceiling / 4) * i;
    svg.append(
      svgEl("line", {
        class: "grid-line",
        x1: PAD.left,
        x2: W - PAD.right,
        y1: y(value),
        y2: y(value),
      }),
    );
    const label = svgEl("text", {
      class: "axis-label",
      x: PAD.left - 8,
      y: y(value) + 3.5,
      "text-anchor": "end",
    });
    label.textContent = String(Math.round(value));
    svg.append(label);
  }

  // The tooltip lives inside the SVG and moves by x/y attributes, because a
  // positioned HTML tooltip would need an inline style.
  const tip = svgEl("g", { class: "tip", visibility: "hidden" });
  const tipBox = svgEl("rect", { class: "tip-box", rx: 5, height: 22, y: 0 });
  const tipText = svgEl("text", { class: "tip-text", y: 15, "text-anchor": "middle" });
  tip.append(tipBox, tipText);

  series.forEach((point, index) => {
    const x = PAD.left + index * step;
    const empty = point.count === 0;

    const bar = svgEl("rect", {
      class: "bar",
      x: x + (step - barW) / 2,
      y: empty ? PAD.top + plotH - 1 : y(point.count),
      width: barW,
      height: empty ? 1 : Math.max(1, plotH - (y(point.count) - PAD.top)),
      rx: Math.min(4, barW / 2),
    });
    if (empty) bar.setAttribute("opacity", "0.22");

    const label = new Date(`${point.day}T00:00:00Z`).toLocaleDateString("en-GB", {
      day: "numeric",
      month: "short",
    });

    // A full height transparent target, so a zero day is still hoverable.
    const hit = svgEl("rect", { class: "hit", x, y: PAD.top, width: step, height: plotH });

    hit.addEventListener("pointerenter", () => {
      bar.classList.add("is-active");
      tipText.textContent = `${point.count} on ${label}`;
      const width = Math.max(64, tipText.textContent.length * 7 + 18);
      const centre = Math.min(W - width / 2 - 4, Math.max(width / 2 + 4, x + step / 2));
      const topY = Math.max(0, (empty ? PAD.top + plotH : y(point.count)) - 28);

      tipBox.setAttribute("width", width);
      tipBox.setAttribute("x", centre - width / 2);
      tipBox.setAttribute("y", topY);
      tipText.setAttribute("x", centre);
      tipText.setAttribute("y", topY + 15);
      tip.setAttribute("visibility", "visible");
    });
    hit.addEventListener("pointerleave", () => {
      bar.classList.remove("is-active");
      tip.setAttribute("visibility", "hidden");
    });

    svg.append(bar, hit);

    // Label the ends and the middle only. A date under every bar is unreadable.
    if (index === 0 || index === series.length - 1 || index === Math.floor(series.length / 2)) {
      const tick = svgEl("text", {
        class: "axis-label",
        x: x + step / 2,
        y: H - 8,
        "text-anchor":
          index === 0 ? "start" : index === series.length - 1 ? "end" : "middle",
      });
      tick.textContent = label;
      svg.append(tick);
    }
  });

  svg.append(tip);
  return el("div", { class: "chart" }, [svg]);
}

// --- table ------------------------------------------------------------------

function accountsTable(accounts) {
  if (accounts.length === 0) {
    return el("p", { class: "soft mt-18", text: "No accounts yet." });
  }

  const head = el(
    "tr",
    {},
    ["Email", "Plan", "Items", "Confirmed", "Joined", "Last seen", "Renews"].map((text) =>
      el("th", { text }),
    ),
  );

  const rows = accounts.map((account) => {
    const warn = account.planStatus === "past_due" || account.planStatus === "canceled";
    return el("tr", {}, [
      el("td", { class: "email", text: account.email }),
      el("td", {}, [
        el("span", {
          class: "badge",
          dataset: { plan: account.plan, warn: String(warn) },
          text: account.planStatus ? `${account.plan} (${account.planStatus})` : account.plan,
        }),
      ]),
      el("td", { text: account.items.toLocaleString() }),
      el("td", { text: account.verified ? "yes" : "no" }),
      el("td", { text: relativeTime(account.createdAt) }),
      el("td", { text: account.lastLoginAt ? relativeTime(account.lastLoginAt) : "never" }),
      el("td", {
        text: account.planPeriodEnd
          ? new Date(account.planPeriodEnd).toLocaleDateString("en-GB")
          : "",
      }),
    ]);
  });

  return el("div", { class: "table-scroll" }, [
    el("table", { class: "accounts" }, [el("thead", {}, [head]), el("tbody", {}, rows)]),
  ]);
}
