/**
 * Builds the browser extension for each browser from the one source folder.
 *
 *   dist/extension/chrome    load unpacked in Chrome, Edge, Brave or Opera
 *   dist/extension/firefox   load as a temporary add-on, or sign through AMO
 *   dist/extension/safari    input for Apple's converter, which needs a Mac
 *
 * plus dist/kalmpass-chrome-<version>.zip and dist/kalmpass-firefox-<version>.zip,
 * ready to upload to the Chrome Web Store and addons.mozilla.org.
 *
 * The code is identical in all three. Only the manifest differs, because the
 * browsers disagree about how a background script is declared and about which
 * keys they will tolerate.
 *
 * Zero dependencies: the zip writer below is the few dozen lines a store
 * upload actually needs.
 */

import { deflateRawSync, crc32 } from "node:zlib";
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";

const SOURCE = "extension";
const OUT = join("dist", "extension");

/** Firefox needs a fixed id to keep storage across updates and to be signed. */
const GECKO_ID = "extension@kalmpass.net";

/** Data collection has to be declared up front for Firefox (140 and later). */
const FIREFOX_MIN = "140.0";

const base = JSON.parse(readFileSync(join(SOURCE, "manifest.json"), "utf8"));

const manifests = {
  chrome: () => base,

  firefox: () => {
    const { minimum_chrome_version: _, background, ...rest } = structuredClone(base);
    return {
      ...rest,
      // Firefox runs the background as an event page rather than a service
      // worker. Same file, same module, different key.
      background: { scripts: [background.service_worker], type: background.type },
      browser_specific_settings: {
        gecko: {
          id: GECKO_ID,
          strict_min_version: FIREFOX_MIN,
          data_collection_permissions: {
            // Your email and a key derived from your master password are sent
            // to KalmPass to sign in. Nothing else leaves unencrypted.
            required: ["authenticationInfo", "personallyIdentifyingInfo"],
          },
        },
      },
    };
  },

  safari: () => {
    const { minimum_chrome_version: _, ...rest } = structuredClone(base);
    return {
      ...rest,
      browser_specific_settings: { safari: { strict_min_version: "16.4" } },
    };
  },
};

// --- zip ----------------------------------------------------------------------

function filesUnder(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? filesUnder(path) : [path];
  });
}

/** DOS time and date for a fixed moment, so the same input gives the same zip. */
const DOS_TIME = 0;
const DOS_DATE = ((2026 - 1980) << 9) | (1 << 5) | 1;

function zip(dir, target) {
  const locals = [];
  const centrals = [];
  let offset = 0;

  for (const path of filesUnder(dir).sort()) {
    const name = Buffer.from(relative(dir, path).split(sep).join("/"));
    const data = readFileSync(path);
    const packed = deflateRawSync(data, { level: 9 });
    const checksum = crc32(data);

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4); // version needed
    local.writeUInt16LE(0x0800, 6); // names are UTF-8
    local.writeUInt16LE(8, 8); // deflate
    local.writeUInt16LE(DOS_TIME, 10);
    local.writeUInt16LE(DOS_DATE, 12);
    local.writeUInt32LE(checksum, 14);
    local.writeUInt32LE(packed.length, 18);
    local.writeUInt32LE(data.length, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4); // made by
    central.writeUInt16LE(20, 6); // needed
    central.writeUInt16LE(0x0800, 8);
    central.writeUInt16LE(8, 10);
    central.writeUInt16LE(DOS_TIME, 12);
    central.writeUInt16LE(DOS_DATE, 14);
    central.writeUInt32LE(checksum, 16);
    central.writeUInt32LE(packed.length, 20);
    central.writeUInt32LE(data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);

    locals.push(local, name, packed);
    centrals.push(central, name);
    offset += local.length + name.length + packed.length;
  }

  const directory = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(centrals.length / 2, 8);
  end.writeUInt16LE(centrals.length / 2, 10);
  end.writeUInt32LE(directory.length, 12);
  end.writeUInt32LE(offset, 16);

  writeFileSync(target, Buffer.concat([...locals, directory, end]));
}

// --- build --------------------------------------------------------------------

rmSync(OUT, { recursive: true, force: true });

for (const [browser, manifest] of Object.entries(manifests)) {
  const dir = join(OUT, browser);
  mkdirSync(dir, { recursive: true });
  cpSync(SOURCE, dir, { recursive: true });
  writeFileSync(join(dir, "manifest.json"), JSON.stringify(manifest(), null, 2) + "\n");

  if (browser !== "safari") {
    const target = join("dist", `kalmpass-${browser}-${base.version}.zip`);
    zip(dir, target);
    console.log(`built ${dir}  and  ${target}`);
  } else {
    console.log(`built ${dir}  (convert on a Mac, see README)`);
  }
}
