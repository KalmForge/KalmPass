/**
 * Optional lookups that reach outside the instance.
 *
 * Nothing here runs unless you press the button for it. KalmPass makes no
 * outbound request of any kind during normal use.
 */

import { loadUser, planOf } from "../accounts";
import { HttpError, badRequest, json, readJson, requireString } from "../http";
import type { Session } from "../sessions";

/**
 * POST /api/tools/breach. Have I Been Pwned range lookup.
 *
 * k-anonymity: the browser SHA-1s the password locally and sends only the first
 * five hex characters. HIBP returns every suffix under that prefix. Hundreds of
 * hashes, and the browser checks for its own among them. The password, and
 * which of the returned hashes was yours, never leave the device.
 *
 * It is proxied rather than called directly so that HIBP sees the Worker rather
 * than your IP address, and so the page keeps a connect-src of 'self' only.
 */
export async function breachCheck(
  env: Env,
  request: Request,
  session: Session,
): Promise<Response> {
  if (!planOf(await loadUser(env, session.userId)).breachCheck) {
    throw new HttpError(
      403,
      "upgrade_required",
      "Breach monitoring is part of Pro.",
      { plan: "pro" },
    );
  }

  const prefix = requireString(await readJson(request), "prefix", { max: 5 });
  if (!/^[0-9A-Fa-f]{5}$/.test(prefix)) {
    throw badRequest('"prefix" must be five hex characters.');
  }

  const upstream = await fetch(`https://api.pwnedpasswords.com/range/${prefix.toUpperCase()}`, {
    // Padding makes every response a similar size, so an observer watching
    // traffic cannot infer anything from the length of the reply.
    headers: { "Add-Padding": "true", "User-Agent": "KalmPass" },
    cf: { cacheTtl: 3600, cacheEverything: true },
  });

  if (!upstream.ok) {
    return json(
      { error: "upstream", message: "The breach database could not be reached." },
      { status: 502 },
    );
  }

  return json({ suffixes: await upstream.text() });
}
