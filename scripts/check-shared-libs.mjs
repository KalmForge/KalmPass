/**
 * The extension carries its own copy of the crypto modules, because a Chrome
 * extension cannot import from the website. Copies drift, and a drifted crypto
 * module is the kind of bug that silently stops a vault opening, so this fails
 * the build if they stop matching.
 */

import { readFileSync } from "node:fs";

const PAIRS = [
  ["public/js/crypto.js", "extension/lib/crypto.js"],
  ["public/js/totp.js", "extension/lib/totp.js"],
];

let failed = false;
for (const [source, copy] of PAIRS) {
  if (readFileSync(source, "utf8") === readFileSync(copy, "utf8")) {
    console.log(`ok  ${copy} matches ${source}`);
    continue;
  }
  console.error(`::error::${copy} has drifted from ${source}. Copy it across again.`);
  failed = true;
}
if (failed) process.exit(1);

/**
 * The advertised price and the configured price must agree.
 *
 * A landing page promising one figure while checkout charges another is not a
 * typo, it is a consumer law problem, and it is exactly the sort of thing that
 * drifts when one of them is edited in a hurry.
 */
const config = readFileSync("wrangler.jsonc", "utf8");
const landing = readFileSync("public/index.html", "utf8");

const SYMBOLS = { GBP: "\u00a3", USD: "$", EUR: "\u20ac" };

const configured = {
  price: /"PRO_PRICE":\s*"([^"]+)"/.exec(config)?.[1],
  interval: /"PRO_INTERVAL":\s*"([^"]+)"/.exec(config)?.[1],
  currency: /"PRO_CURRENCY":\s*"([^"]+)"/.exec(config)?.[1],
};
const symbol = SYMBOLS[configured.currency];
if (!symbol) {
  console.error(`::error::No symbol known for currency ${configured.currency}.`);
  process.exit(1);
}
const advertised = new RegExp(
  '<p class="amount">\\' + symbol + '(\\d+)\\s*<small>a (year|month)</small></p>',
).exec(landing);

if (!advertised) {
  console.error("::error::Could not find the Pro price on the landing page.");
  process.exit(1);
}
if (advertised[1] !== configured.price || advertised[2] !== configured.interval) {
  console.error(
    `::error::The landing page says ${symbol}${advertised[1]} a ${advertised[2]} but wrangler.jsonc ` +
      `says ${symbol}${configured.price} a ${configured.interval}. They have to agree, and both have ` +
      `to match the Stripe price.`,
  );
  process.exit(1);
}
console.log(
  `ok  landing page and config agree on ${symbol}${configured.price} a ${configured.interval}`,
);
