/**
 * Copies the web app into www/, which Capacitor packages into the apps.
 *
 * Nothing is rewritten except the page's head: the apps get their own
 * Content-Security-Policy (the website's comes from a response header, which a
 * packaged app does not have), lose the web manifest, and load Capacitor's
 * runtime before the app starts.
 */

import { copyFileSync, cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const mobile = join(here, "..");
const site = join(mobile, "..", "public");
const out = join(mobile, "www");

const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "connect-src https://kalmpass.net",
  "object-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

rmSync(out, { recursive: true, force: true });
mkdirSync(out, { recursive: true });

// The admin dashboard is a website page and has no place in the app.
cpSync(join(site, "js"), join(out, "js"), {
  recursive: true,
  filter: (source) => !source.endsWith("admin.js"),
});
for (const file of ["app.css", "icon.svg"]) copyFileSync(join(site, file), join(out, file));
copyFileSync(
  join(mobile, "node_modules", "@capacitor", "core", "dist", "capacitor.js"),
  join(out, "capacitor.js"),
);
copyFileSync(join(here, "native.js"), join(out, "native.js"));

let page = readFileSync(join(site, "app", "index.html"), "utf8");
const replace = (from, to) => {
  if (!page.includes(from)) throw new Error(`build-web: the app page no longer contains ${from}`);
  page = page.replace(from, to);
};

replace(`    <link rel="manifest" href="/manifest.webmanifest" />\n`, "");
replace(
  `    <meta charset="utf-8" />\n`,
  `    <meta charset="utf-8" />\n    <meta http-equiv="Content-Security-Policy" content="${CSP}" />\n`,
);
replace(
  `  </head>`,
  `    <script src="/capacitor.js"></script>\n    <script src="/native.js"></script>\n  </head>`,
);

writeFileSync(join(out, "index.html"), page);
console.log(`web app copied to ${out}`);
