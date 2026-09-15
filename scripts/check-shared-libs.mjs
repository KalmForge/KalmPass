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
process.exit(failed ? 1 : 0);
