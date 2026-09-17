/**
 * Looking after SERVER_KEY.
 *
 * Every row in the database is sealed with keys derived from SERVER_KEY. If the
 * Worker secret and every copy of it are lost, the database cannot be read, and
 * nor can any backup. This script helps keep copies that are known to be good.
 *
 *   npm run key:check            fingerprint of the key in secrets.local.txt
 *   npm run key:check -- <key>   fingerprint of a key typed back from a copy
 *   npm run key:sheet            a printable sheet in private/, never committed
 *
 * The fingerprint is the same one the admin dashboard shows and each backup
 * records, so matching all three proves a copy is the one in use. It is a
 * separate HKDF branch and says nothing about the key itself.
 */

import { hkdfSync } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";

const [command, typed] = process.argv.slice(2);

function keyFromSecretsFile() {
  const text = readFileSync("secrets.local.txt", "utf8");
  const match = /SERVER_KEY[^\n]*\n\s+(\S+)/.exec(text);
  if (!match) throw new Error("No SERVER_KEY found in secrets.local.txt.");
  return match[1];
}

function fingerprint(key) {
  const raw = Buffer.from(key.replace(/\s+/g, ""), "base64");
  if (raw.length < 32) throw new Error("That is not a valid SERVER_KEY (too short).");
  const bits = Buffer.from(hkdfSync("sha256", raw, Buffer.alloc(0), "kalmpass/v1/fingerprint", 8));
  return bits.toString("hex").match(/.{4}/g).join("-");
}

const escape = (s) => s.replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);

function sheet(key) {
  const print = fingerprint(key);
  const groups = key.match(/.{1,4}/g).join(" ");
  const today = new Date().toISOString().slice(0, 10);
  return `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>KalmPass server key</title>
<style>
  body { font: 15px/1.5 system-ui, sans-serif; max-width: 640px; margin: 40px auto; color: #111; }
  h1 { font-size: 22px; margin: 0 0 4px; }
  .key { font: 22px/1.8 ui-monospace, Consolas, monospace; letter-spacing: 1px; border: 2px solid #111; padding: 16px; word-spacing: 6px; }
  .fp { font: 18px ui-monospace, Consolas, monospace; }
  li { margin: 6px 0; }
</style>
<h1>KalmPass server key</h1>
<p>Printed ${today}. Keep this somewhere safe and offline, such as a locked drawer or a safe.
Keep a second copy in a different place.</p>
<h2>SERVER_KEY</h2>
<p class="key">${escape(groups)}</p>
<p>Type it back without the spaces.</p>
<h2>Fingerprint</h2>
<p class="fp">${print}</p>
<p>The admin dashboard and every backup show this fingerprint. If they match, this copy is the one in use.
To check a copy: <code>npm run key:check -- &lt;the key&gt;</code></p>
<h2>If the server key is ever lost from Cloudflare</h2>
<ol>
  <li>Run <code>npx wrangler secret put SERVER_KEY</code> in the KalmPass folder and paste the key.</li>
  <li>Open the admin dashboard and confirm the fingerprint matches the one above.</li>
</ol>
<p>Anyone holding this key and a copy of the database can read email addresses and account
details, but still cannot open a single vault. Treat it like the keys to the office.</p>
</html>
`;
}

if (command === "check") {
  const key = typed ?? keyFromSecretsFile();
  console.log(`Fingerprint: ${fingerprint(key)}`);
  console.log("Compare it with the Server key tile on the admin dashboard.");
} else if (command === "sheet") {
  mkdirSync("private", { recursive: true });
  const file = "private/server-key-sheet.html";
  writeFileSync(file, sheet(keyFromSecretsFile()));
  console.log(`Wrote ${file}. Open it, print it, then delete the file:`);
  console.log(`  del ${file.replace("/", "\\")}`);
} else {
  console.log("Usage: node scripts/server-key.mjs check [key] | sheet");
  process.exit(1);
}
