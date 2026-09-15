/**
 * Password and passphrase generation.
 *
 * Every random choice comes from `crypto.getRandomValues` via rejection
 * sampling. `Math.random()` appears nowhere in this file, and the modulo bias
 * that `% n` would introduce is avoided explicitly, a generator that quietly
 * favours some characters is a generator that quietly loses you entropy.
 */

import { WORDS } from "./words.js";

const SETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  digits: "0123456789",
  symbols: "!#$%&*+-=?@^_~",
};

/** Characters that are easy to confuse when read off a screen or written down. */
const AMBIGUOUS = new Set("Il1O0oB8S5Z2");

/** Uniform in [0, max). Draws again rather than folding the remainder in. */
function randomInt(max) {
  if (max <= 0) throw new RangeError("max must be positive");
  const limit = Math.floor(0xffffffff / max) * max;
  const buffer = new Uint32Array(1);
  let value;
  do {
    crypto.getRandomValues(buffer);
    value = buffer[0];
  } while (value >= limit);
  return value % max;
}

const pick = (list) => list[randomInt(list.length)];

function shuffle(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [array[i], array[j]] = [array[j], array[i]];
  }
  return array;
}

export const DEFAULT_PASSWORD_OPTIONS = Object.freeze({
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
  requireEach: true,
});

export function generatePassword(options = {}) {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  const length = Math.max(4, Math.min(128, Math.round(opts.length)));

  const active = ["lower", "upper", "digits", "symbols"]
    .filter((name) => opts[name])
    .map((name) => {
      const chars = [...SETS[name]];
      return opts.avoidAmbiguous ? chars.filter((c) => !AMBIGUOUS.has(c)) : chars;
    })
    .filter((chars) => chars.length > 0);

  // Refusing every class would otherwise produce an empty string, which is a
  // far worse outcome than quietly falling back to letters.
  const pools = active.length > 0 ? active : [[...SETS.lower]];
  const combined = pools.flat();

  const chars = [];
  if (opts.requireEach && pools.length <= length) {
    for (const pool of pools) chars.push(pick(pool));
  }
  while (chars.length < length) chars.push(pick(combined));

  return shuffle(chars).join("");
}

export const DEFAULT_PASSPHRASE_OPTIONS = Object.freeze({
  words: 5,
  separator: "-",
  capitalize: true,
  includeNumber: true,
});

export function generatePassphrase(options = {}) {
  const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  const count = Math.max(3, Math.min(12, Math.round(opts.words)));

  const chosen = Array.from({ length: count }, () => {
    const word = pick(WORDS);
    return opts.capitalize ? word[0].toUpperCase() + word.slice(1) : word;
  });

  if (opts.includeNumber) {
    // Appended to a randomly chosen word rather than always the last, so the
    // digit's position carries information too.
    const index = randomInt(chosen.length);
    chosen[index] += String(randomInt(10));
  }
  return chosen.join(opts.separator);
}

// --- strength ---------------------------------------------------------------

export function passphraseEntropy(options = {}) {
  const opts = { ...DEFAULT_PASSPHRASE_OPTIONS, ...options };
  const count = Math.max(3, Math.min(12, Math.round(opts.words)));
  const base = count * Math.log2(WORDS.length);
  // The digit adds its value and its position.
  return base + (opts.includeNumber ? Math.log2(10) + Math.log2(count) : 0);
}

export function passwordEntropy(options = {}) {
  const opts = { ...DEFAULT_PASSWORD_OPTIONS, ...options };
  const length = Math.max(4, Math.min(128, Math.round(opts.length)));
  let pool = 0;
  for (const name of ["lower", "upper", "digits", "symbols"]) {
    if (!opts[name]) continue;
    const chars = [...SETS[name]];
    pool += opts.avoidAmbiguous ? chars.filter((c) => !AMBIGUOUS.has(c)).length : chars.length;
  }
  return length * Math.log2(pool || SETS.lower.length);
}

/**
 * A rough entropy estimate for a password someone else chose. Used by the
 * health report, where we cannot know how it was generated.
 *
 * Deliberately pessimistic: it detects the obvious patterns (repeats, runs,
 * dictionary words, keyboard walks) and discounts for them, so a password it
 * calls strong is unlikely to be weak. It is not a substitute for zxcvbn.
 */
export function estimateStrength(password) {
  if (!password) return { bits: 0, label: "empty", score: 0 };

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;

  let bits = password.length * Math.log2(pool || 1);

  const lower = password.toLowerCase();
  if (/^(.)\1+$/.test(password)) bits *= 0.15;
  else if (/(.)\1{2,}/.test(password)) bits *= 0.7;

  if (/^\d+$/.test(password)) bits *= 0.55;
  if (/(012|123|234|345|456|567|678|789|890|abc|xyz)/.test(lower)) bits *= 0.75;
  if (/(qwer|asdf|zxcv|qaz|wsx|1qaz)/.test(lower)) bits *= 0.6;

  // A trailing year or "123!" is the most common human flourish and adds far
  // less than its character count suggests.
  if (/^[a-z]+([0-9]{1,4}|[0-9]{1,4}[!?.@#$]{0,2})$/.test(lower)) bits *= 0.65;

  const stripped = lower.replace(/[^a-z]/g, "");
  if (stripped.length >= 4 && WORDS.includes(stripped)) bits = Math.min(bits, 12);

  bits = Math.max(0, Math.round(bits));
  const score = bits < 40 ? 0 : bits < 60 ? 1 : bits < 80 ? 2 : bits < 100 ? 3 : 4;
  const label = ["very weak", "weak", "fair", "strong", "very strong"][score];
  return { bits, label, score };
}

/** Plain-language time-to-crack, assuming a well-funded offline attacker. */
export function crackTime(bits) {
  const GUESSES_PER_SECOND = 1e12;
  const seconds = 2 ** Math.max(0, bits - 1) / GUESSES_PER_SECOND;
  const units = [
    ["second", 1],
    ["minute", 60],
    ["hour", 3600],
    ["day", 86_400],
    ["year", 31_536_000],
    ["century", 3_153_600_000],
  ];
  if (seconds < 1) return "instantly";
  let best = units[0];
  for (const unit of units) if (seconds >= unit[1]) best = unit;
  const n = seconds / best[1];
  if (best[0] === "century" && n > 1e6) return "longer than the universe has existed";
  const rounded = n >= 10 ? Math.round(n) : Math.round(n * 10) / 10;
  return `${rounded.toLocaleString()} ${best[0]}${rounded === 1 ? "" : "s"}`;
}
