/**
 * Renders the KalmPass mark to PNG: the extension's icons, and the iOS and
 * Android app icons and launch screens.
 *
 * Extensions and app stores cannot use SVG, and pulling in an image library to
 * convert one would mean adding a dependency to a project whose whole claim is
 * that it has none. A PNG is a handful of chunks around a zlib stream, so this
 * rasterises the shapes directly and writes the file itself.
 *
 * Run with `npm run icons` after changing public/icon.svg.
 */

import { deflateSync } from "node:zlib";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

// Sampled from public/icon.svg so the two stay in step.
const NAVY_LIGHT = [17, 65, 155];
const NAVY_DARK = [6, 22, 52];
const SHACKLE = [235, 248, 255];
const BODY_TEAL = [60, 230, 196];
const BODY_ICE = [234, 248, 255];
const BODY_BLUE = [28, 99, 207];
const KEYHOLE = [10, 37, 89];

const mix = (a, b, t) => a.map((v, i) => Math.round(v + (b[i] - v) * Math.min(1, Math.max(0, t))));

/** Signed distance to a rounded rectangle, used for antialiased edges. */
function roundRect(px, py, x, y, w, h, r) {
  const dx = Math.max(x - px, px - (x + w), 0);
  const dy = Math.max(y - py, py - (y + h), 0);
  const inset = Math.min(Math.min(px - x, x + w - px), Math.min(py - y, y + h - py));

  if (dx === 0 && dy === 0) {
    // Inside the box: only the corners can still be outside the rounding.
    const cx = Math.min(Math.max(px, x + r), x + w - r);
    const cy = Math.min(Math.max(py, y + r), y + h - r);
    return Math.hypot(px - cx, py - cy) - r + Math.min(0, -inset);
  }
  return Math.hypot(dx, dy);
}

const coverage = (distance) => Math.min(1, Math.max(0, 0.5 - distance));

/** The padlock itself, in the SVG's 512 box. Null where it is not. */
function glyph(px, py, s) {
  let colour = null;

  // Shackle: the ring between two circles, clipped above the body.
  const ringDistance = Math.abs(Math.hypot(px - 257, py - 176) - 85) - 22;
  if (py < 200 && coverage(ringDistance * s) > 0.5) colour = SHACKLE;

  // Body, with the teal to blue sweep and the K chevron over it.
  if (coverage(roundRect(px, py, 118, 182, 278, 258, 34) * s) > 0.5) {
    const t = (px - 118) / 278;
    colour = t < 0.45 ? mix(BODY_TEAL, BODY_ICE, t / 0.45) : mix(BODY_ICE, BODY_BLUE, (t - 0.45) / 0.55);

    // Distance to the two chevron arms meeting at the keyhole.
    const arm = (ax, ay, bx, by) => {
      const vx = bx - ax;
      const vy = by - ay;
      const u = Math.min(1, Math.max(0, ((px - ax) * vx + (py - ay) * vy) / (vx * vx + vy * vy)));
      return Math.hypot(px - (ax + u * vx), py - (ay + u * vy));
    };
    const chevron = Math.min(arm(404, 186, 268, 311), arm(268, 311, 404, 436)) - 27;
    if (coverage(chevron * s) > 0.5) colour = BODY_ICE;

    if (Math.hypot(px - 212, py - 303) < 25) colour = KEYHOLE;
    if (px > 203 && px < 221 && py > 303 && py < 361) colour = KEYHOLE;
  }
  return colour;
}

/**
 * Draws a width by height image.
 *
 *   background "tile"   the rounded tile, as in the SVG, transparent around it
 *   background "fill"   the navy gradient edge to edge, fully opaque
 *   background "none"   the padlock alone on transparency
 *
 * `scale` is the size of the 512 box relative to the shorter side, so a value
 * below 1 leaves margin, as launch screens and adaptive icons need.
 */
function render(width, height, { background = "tile", scale = 1 } = {}) {
  const box = Math.min(width, height) * scale;
  const s = box / 512;
  const left = (width - box) / 2;
  const top = (height - box) / 2;
  const pixels = new Uint8Array(width * height * 4);
  // Supersample, or the shackle looks like a staircase at 16px.
  const SUB = Math.max(width, height) > 512 ? 2 : 3;

  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      let acc = [0, 0, 0];
      let hits = 0;

      for (let sy = 0; sy < SUB; sy++) {
        for (let sx = 0; sx < SUB; sx++) {
          const cx = x + (sx + 0.5) / SUB;
          const cy = y + (sy + 0.5) / SUB;
          const px = (cx - left) / s;
          const py = (cy - top) / s;

          let colour = null;
          if (background === "fill") {
            colour = mix(NAVY_LIGHT, NAVY_DARK, (cx / width + cy / height) / 2 + 0.1);
          } else if (background === "tile") {
            if (coverage(roundRect(px, py, 0, 0, 512, 512, 116) * s) > 0) {
              colour = mix(NAVY_LIGHT, NAVY_DARK, (px + py) / 1024 + 0.1);
            }
          }
          if (background !== "tile" || colour) colour = glyph(px, py, s) ?? colour;
          if (!colour) continue;

          acc = [acc[0] + colour[0], acc[1] + colour[1], acc[2] + colour[2]];
          hits++;
        }
      }

      if (hits === 0) continue;
      const i = (y * width + x) * 4;
      pixels[i] = Math.round(acc[0] / hits);
      pixels[i + 1] = Math.round(acc[1] / hits);
      pixels[i + 2] = Math.round(acc[2] / hits);
      pixels[i + 3] = Math.round((hits / (SUB * SUB)) * 255);
    }
  }
  return pixels;
}

// --- PNG container ----------------------------------------------------------

const CRC = (() => {
  const table = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c;
  }
  return (buf) => {
    let c = -1;
    for (const b of buf) c = table[(c ^ b) & 0xff] ^ (c >>> 8);
    return (c ^ -1) >>> 0;
  };
})();

function chunk(type, data) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, "ascii"), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(CRC(body));
  return Buffer.concat([length, body, crc]);
}

/**
 * RGBA normally. `opaque` writes RGB with no alpha channel at all, which the
 * App Store insists on for the app icon.
 */
function png(width, height, pixels, { opaque = false } = {}) {
  const channels = opaque ? 3 : 4;
  const header = Buffer.alloc(13);
  header.writeUInt32BE(width, 0);
  header.writeUInt32BE(height, 4);
  header[8] = 8; // bit depth
  header[9] = opaque ? 2 : 6; // truecolour, with or without alpha
  // Each scanline is prefixed with its filter type; 0 means none.
  const stride = width * channels + 1;
  const raw = Buffer.alloc(height * stride);
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const from = (y * width + x) * 4;
      const to = y * stride + 1 + x * channels;
      for (let c = 0; c < channels; c++) raw[to + c] = pixels[from + c];
    }
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

function write(file, width, height, options = {}) {
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, png(width, height, render(width, height, options), options));
  console.log(`wrote ${file}`);
}

/** Width and height from an existing PNG, so launch screens keep their sizes. */
function sizeOf(file) {
  const head = readFileSync(file);
  return [head.readUInt32BE(16), head.readUInt32BE(20)];
}

// --- the browser extension ----------------------------------------------------

for (const size of [16, 32, 48, 128]) {
  write(join("extension", "icons", `icon-${size}.png`), size, size);
}

// --- iOS ----------------------------------------------------------------------

const ios = join("mobile", "ios", "App", "App", "Assets.xcassets");
if (existsSync(ios)) {
  // iOS rounds the corners itself, and rejects an icon with transparency.
  write(join(ios, "AppIcon.appiconset", "AppIcon-512@2x.png"), 1024, 1024, {
    background: "fill",
    scale: 0.86,
    opaque: true,
  });
  for (const name of readdirSync(join(ios, "Splash.imageset")).filter((f) => f.endsWith(".png"))) {
    const file = join(ios, "Splash.imageset", name);
    const [w, h] = sizeOf(file);
    write(file, w, h, { background: "fill", scale: 0.28, opaque: true });
  }
}

// --- Android ------------------------------------------------------------------

const res = join("mobile", "android", "app", "src", "main", "res");
if (existsSync(res)) {
  const densities = { mdpi: 1, hdpi: 1.5, xhdpi: 2, xxhdpi: 3, xxxhdpi: 4 };
  for (const [name, factor] of Object.entries(densities)) {
    const dir = join(res, `mipmap-${name}`);
    const legacy = Math.round(48 * factor);
    write(join(dir, "ic_launcher.png"), legacy, legacy);
    write(join(dir, "ic_launcher_round.png"), legacy, legacy);
    // Adaptive icons are 108dp with only the middle 66dp certain to show.
    const adaptive = Math.round(108 * factor);
    write(join(dir, "ic_launcher_foreground.png"), adaptive, adaptive, {
      background: "none",
      scale: 0.62,
    });
  }

  writeFileSync(
    join(res, "values", "ic_launcher_background.xml"),
    `<?xml version="1.0" encoding="utf-8"?>\n<resources>\n    <color name="ic_launcher_background">#0B2A63</color>\n</resources>\n`,
  );

  for (const dir of readdirSync(res).filter((d) => d.startsWith("drawable"))) {
    const file = join(res, dir, "splash.png");
    if (!existsSync(file)) continue;
    const [w, h] = sizeOf(file);
    write(file, w, h, { background: "fill", scale: 0.28, opaque: true });
  }
}
