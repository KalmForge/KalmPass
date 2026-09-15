/**
 * Renders the KalmPass mark to PNG at the sizes Chrome wants.
 *
 * Chrome extensions cannot use SVG icons, and pulling in an image library to
 * convert one would mean adding a dependency to a project whose whole claim is
 * that it has none. A PNG is a handful of chunks around a zlib stream, so this
 * rasterises the shapes directly and writes the file itself.
 *
 * Run with `npm run icons` after changing public/icon.svg.
 */

import { deflateSync } from "node:zlib";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const OUT = "extension/icons";
const SIZES = [16, 32, 48, 128];

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

function blend(dst, src, alpha) {
  return dst.map((v, i) => Math.round(v + (src[i] - v) * alpha));
}

function render(size) {
  const s = size / 512; // The SVG is authored in a 512 box.
  const pixels = new Uint8Array(size * size * 4);
  // Supersample, or the shackle looks like a staircase at 16px.
  const SUB = 3;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      let acc = [0, 0, 0];
      let hits = 0;

      for (let sy = 0; sy < SUB; sy++) {
        for (let sx = 0; sx < SUB; sx++) {
          const px = (x + (sx + 0.5) / SUB) / s;
          const py = (y + (sy + 0.5) / SUB) / s;

          const inBackground = coverage(roundRect(px, py, 0, 0, 512, 512, 116) * s);
          if (inBackground <= 0) continue;

          // Diagonal gradient across the tile.
          let colour = mix(NAVY_LIGHT, NAVY_DARK, (px + py) / 1024 + 0.1);

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

          acc = [acc[0] + colour[0], acc[1] + colour[1], acc[2] + colour[2]];
          hits++;
        }
      }

      const total = SUB * SUB;
      const alpha = hits / total;
      const i = (y * size + x) * 4;
      if (hits === 0) continue;

      const avg = acc.map((v) => Math.round(v / hits));
      pixels[i] = avg[0];
      pixels[i + 1] = avg[1];
      pixels[i + 2] = avg[2];
      pixels[i + 3] = Math.round(alpha * 255);
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

function png(size, pixels) {
  const header = Buffer.alloc(13);
  header.writeUInt32BE(size, 0);
  header.writeUInt32BE(size, 4);
  header[8] = 8; // bit depth
  header[9] = 6; // truecolour with alpha
  // Each scanline is prefixed with its filter type; 0 means none.
  const raw = Buffer.alloc(size * (size * 4 + 1));
  for (let y = 0; y < size; y++) {
    raw[y * (size * 4 + 1)] = 0;
    Buffer.from(pixels.buffer, y * size * 4, size * 4).copy(raw, y * (size * 4 + 1) + 1);
  }

  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk("IHDR", header),
    chunk("IDAT", deflateSync(raw, { level: 9 })),
    chunk("IEND", Buffer.alloc(0)),
  ]);
}

mkdirSync(OUT, { recursive: true });
for (const size of SIZES) {
  const file = join(OUT, `icon-${size}.png`);
  mkdirSync(dirname(file), { recursive: true });
  writeFileSync(file, png(size, render(size)));
  console.log(`wrote ${file}`);
}
