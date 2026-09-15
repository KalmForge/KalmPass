/**
 * Sets the Stripe secrets from a local file, then deletes the file.
 *
 * Wrangler's interactive prompt is unreliable when it is not driven by a real
 * terminal: it will happily read the next line of the script as the secret
 * value, which stores a shell command where an API key should be. Piping the
 * value in on stdin avoids the prompt entirely.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";

const FILE = "stripe.txt";
const EXPECTED = {
  STRIPE_SECRET_KEY: /^(sk|rk)_(test|live)_[A-Za-z0-9]+$/,
  STRIPE_PRICE_ID: /^price_[A-Za-z0-9]+$/,
  STRIPE_WEBHOOK_SECRET: /^whsec_[A-Za-z0-9]+$/,
};

if (!existsSync(FILE)) {
  console.error(`No ${FILE} found. Create it with one NAME=value per line.`);
  process.exit(1);
}

const values = new Map();
for (const line of readFileSync(FILE, "utf8").split(/\r?\n/)) {
  const trimmed = line.trim();
  if (!trimmed || trimmed.startsWith("#")) continue;
  const at = trimmed.indexOf("=");
  if (at === -1) continue;
  values.set(trimmed.slice(0, at).trim(), trimmed.slice(at + 1).trim());
}

let failed = false;
for (const [name, pattern] of Object.entries(EXPECTED)) {
  const value = values.get(name);
  if (!value) {
    console.error(`Missing ${name}.`);
    failed = true;
  } else if (!pattern.test(value)) {
    // Catches the exact mistake that started this: a shell command where a key
    // should be. Better to refuse than to store rubbish and fail at checkout.
    console.error(`${name} does not look right. Expected ${pattern}, got ${value.length} characters starting "${value.slice(0, 8)}".`);
    failed = true;
  }
}
if (failed) process.exit(1);

for (const name of Object.keys(EXPECTED)) {
  execFileSync("npx", ["wrangler", "secret", "put", name], {
    input: values.get(name),
    stdio: ["pipe", "ignore", "inherit"],
    shell: process.platform === "win32",
  });
  console.log(`set ${name}`);
}

rmSync(FILE);
console.log(`\nDone. ${FILE} deleted.`);
