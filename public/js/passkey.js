/**
 * Unlocking with a passkey.
 *
 * The trick is the WebAuthn PRF extension. A passkey can be asked to produce a
 * deterministic 32 byte secret for a given salt, and it will only ever do so
 * for the site the credential belongs to, after the user has proved themselves
 * to the authenticator with a fingerprint, face or device PIN.
 *
 * That secret behaves exactly like the Recovery Key already does here: stretch
 * it, split it into an encryption branch and an auth branch, wrap the vault key
 * with the first and hand a hash of the second to the server. So a passkey is
 * simply a Recovery Key you do not have to write down, held in your device's
 * secure hardware.
 *
 * Two consequences worth understanding:
 *
 *   - It is phishing resistant for free. A credential is bound to its origin,
 *     so a lookalike site cannot coax the same secret out of the authenticator.
 *
 *   - It does not weaken the zero-knowledge property. The server stores another
 *     wrapped copy of the vault key and a verifier, neither of which it can
 *     open, exactly as with the other two routes in.
 */

const RP_NAME = "KalmPass";

/**
 * A fixed salt. It need not be secret or unique: the credential's own key
 * material already makes each passkey produce a different output. Keeping it
 * constant is what allows a sign-in with no username, because we do not have to
 * look anything up before asking the authenticator.
 */
const PRF_SALT = new TextEncoder().encode("kalmpass/v1/passkey-prf");

export const toB64Url = (bytes) =>
  btoa(String.fromCharCode(...new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const fromB64Url = (text) => {
  const padded = text.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  return Uint8Array.from(binary, (c) => c.charCodeAt(0));
};

/** Whether this browser can do passkeys at all. PRF support is checked in use. */
export function isSupported() {
  return (
    typeof PublicKeyCredential !== "undefined" &&
    typeof navigator.credentials?.create === "function"
  );
}

/** Whether the device has a built-in authenticator, for wording the offer. */
export async function hasPlatformAuthenticator() {
  if (!isSupported()) return false;
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

const randomBytes = (n) => crypto.getRandomValues(new Uint8Array(n));

/**
 * Creates a passkey and returns its id along with the secret it yields.
 *
 * `residentKey: required` makes it discoverable, which is what lets somebody
 * click Unlock and pick an account rather than typing an email first.
 */
export async function createPasskey(email) {
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge: randomBytes(32),
      rp: { name: RP_NAME, id: location.hostname },
      user: {
        // Random rather than the account id: the handle is stored unencrypted
        // on the authenticator, so it should say nothing about the account.
        id: randomBytes(16),
        name: email,
        displayName: email,
      },
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      authenticatorSelection: {
        residentKey: "required",
        userVerification: "required",
      },
      // No attestation: we do not need to know which make of authenticator this
      // is, and asking would be tracking for no benefit.
      attestation: "none",
      extensions: { prf: {} },
      timeout: 120_000,
    },
  });

  if (!credential) throw new Error("No passkey was created.");

  const extensions = credential.getClientExtensionResults();
  if (!extensions?.prf?.enabled) {
    throw new Error(
      "This passkey cannot derive an encryption key, so it cannot unlock a vault. Try a device passkey, or a browser that supports the PRF extension.",
    );
  }

  // The secret itself comes from an assertion. Creation only tells us the
  // authenticator is willing.
  const secret = await readSecret(credential.rawId);
  return { credentialId: toB64Url(credential.rawId), secret };
}

/** Asks the user to choose a passkey, and returns its id and secret. */
export async function usePasskey() {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: location.hostname,
      userVerification: "required",
      // Empty, so the browser offers whichever passkeys it holds for this site.
      allowCredentials: [],
      extensions: { prf: { eval: { first: PRF_SALT } } },
      timeout: 120_000,
    },
  });

  if (!assertion) throw new Error("No passkey was used.");
  const output = assertion.getClientExtensionResults()?.prf?.results?.first;
  if (!output) throw new Error("That passkey did not return an encryption key.");

  return { credentialId: toB64Url(assertion.rawId), secret: new Uint8Array(output) };
}

/** The same, restricted to one credential, used right after creating it. */
async function readSecret(rawId) {
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge: randomBytes(32),
      rpId: location.hostname,
      userVerification: "required",
      allowCredentials: [{ type: "public-key", id: rawId }],
      extensions: { prf: { eval: { first: PRF_SALT } } },
      timeout: 120_000,
    },
  });

  const output = assertion?.getClientExtensionResults()?.prf?.results?.first;
  if (!output) {
    throw new Error("This passkey cannot produce an encryption key on this device.");
  }
  return new Uint8Array(output);
}

export { fromB64Url };
