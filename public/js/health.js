/**
 * Vault health: weak passwords, reused passwords, stale passwords, and — only
 * if you ask for it — passwords that appear in known breach corpora.
 *
 * All of it is computed here against already-decrypted items. The breach check
 * is the single feature in KalmPass that touches the network beyond your own
 * instance, and it uses k-anonymity: see `breachCheck` below.
 */

import { api } from "./api.js";
import { sha1Hex } from "./crypto.js";
import { estimateStrength } from "./generator.js";

const STALE_MS = 365 * 24 * 60 * 60 * 1000;

export function analyse(items) {
  const live = items.filter((item) => !item.deletedAt && item.password);

  // Group by password to find reuse. The map is local and discarded on return.
  const byPassword = new Map();
  for (const item of live) {
    const group = byPassword.get(item.password);
    if (group) group.push(item);
    else byPassword.set(item.password, [item]);
  }

  const reused = [];
  for (const group of byPassword.values()) {
    if (group.length > 1) reused.push(group);
  }

  const weak = [];
  for (const item of live) {
    const strength = estimateStrength(item.password);
    if (strength.score <= 1) weak.push({ item, strength });
  }
  weak.sort((a, b) => a.strength.bits - b.strength.bits);

  const cutoff = Date.now() - STALE_MS;
  const stale = live
    .filter((item) => (item.passwordUpdatedAt ?? item.createdAt ?? 0) < cutoff)
    .sort((a, b) => (a.passwordUpdatedAt ?? 0) - (b.passwordUpdatedAt ?? 0));

  const missingTotp = live.filter((item) => !item.totp && item.url);

  return {
    total: live.length,
    weak,
    reused: reused.sort((a, b) => b.length - a.length),
    stale,
    missingTotp,
    score: scoreOf(live.length, weak.length, reused.flat().length, stale.length),
  };
}

function scoreOf(total, weak, reused, stale) {
  if (total === 0) return 100;
  const penalty = (weak * 3 + reused * 2 + stale) / (total * 3);
  return Math.max(0, Math.round((1 - Math.min(1, penalty)) * 100));
}

/**
 * Have I Been Pwned, without telling them anything.
 *
 * We SHA-1 the password locally, send only the first five hex characters, and
 * receive every suffix sharing that prefix — typically several hundred. The
 * match is found here. HIBP learns a five-character prefix that fits hundreds of
 * thousands of real passwords, and nothing else; the request is proxied through
 * your own Worker, so they do not see your IP either.
 *
 * `onProgress` is called as it goes, because a large vault takes a moment.
 */
export async function breachCheck(items, onProgress) {
  const live = items.filter((item) => !item.deletedAt && item.password);
  const unique = [...new Set(live.map((item) => item.password))];

  const breached = new Map();
  const cache = new Map();
  let done = 0;

  for (const password of unique) {
    const hash = await sha1Hex(password);
    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    if (!cache.has(prefix)) {
      const { suffixes } = await api.breachRange(prefix);
      const counts = new Map();
      for (const line of suffixes.split("\n")) {
        const [candidate, count] = line.trim().split(":");
        if (candidate) counts.set(candidate, Number(count) || 0);
      }
      cache.set(prefix, counts);
    }

    const count = cache.get(prefix).get(suffix);
    if (count) breached.set(password, count);

    onProgress?.(++done, unique.length);
  }

  return live
    .filter((item) => breached.has(item.password))
    .map((item) => ({ item, count: breached.get(item.password) }))
    .sort((a, b) => b.count - a.count);
}
