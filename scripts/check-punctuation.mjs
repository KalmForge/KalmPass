/**
 * House style check: no em dashes, anywhere.
 *
 * They are the single clearest tell that copy was machine-written, and they
 * creep back in easily. A full stop, comma or colon is almost always better.
 *
 * Run with `npm run lint:copy`. Also runs in CI before every deploy.
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const EM_DASH = String.fromCharCode(0x2014);
const EN_DASH = String.fromCharCode(0x2013);

const files = execFileSync("git", ["ls-files"], { encoding: "utf8" })
  .split("\n")
  .filter(Boolean);

const findings = [];

for (const file of files) {
  let text;
  try {
    text = readFileSync(file, "utf8");
  } catch {
    continue; // Binary or unreadable; nothing to check.
  }
  if (!text.includes(EM_DASH) && !text.includes(EN_DASH)) continue;

  text.split("\n").forEach((line, index) => {
    for (const [name, char] of [
      ["em dash", EM_DASH],
      ["en dash", EN_DASH],
    ]) {
      if (line.includes(char)) {
        findings.push({ file, line: index + 1, name, text: line.trim().slice(0, 100) });
      }
    }
  });
}

if (findings.length === 0) {
  console.log("Punctuation check passed. No em or en dashes found.");
  process.exit(0);
}

for (const f of findings) {
  // GitHub Actions picks this format up and annotates the file inline.
  console.log(`::error file=${f.file},line=${f.line}::${f.name} found: ${f.text}`);
  console.log(`  ${f.file}:${f.line}  ${f.text}`);
}
console.log(`\n${findings.length} found. Use a full stop, comma or colon instead.`);
process.exit(1);
