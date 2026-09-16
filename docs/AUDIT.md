# Independent security audit: brief

This is the document to send to an audit firm when asking for a quote. It says
what KalmPass is, what to look at first, what we already know is a trade-off,
and what we expect back. Keep it current: when the code moves, the line counts
and the list of trade-offs should move with it.

## When to book

Book once there is revenue to cover it, and before any of these:

- listing the apps in the App Store or Google Play,
- advertising the extension in the Chrome Web Store or on addons.mozilla.org,
- any marketing that says "audited".

Until then, `SECURITY.md` invites reports, and the code is public under the
AGPL, which is the next best thing.

## What KalmPass is

A zero-knowledge password manager. The master password never leaves the
device. It is stretched with PBKDF2-SHA256 (1,000,000 rounds, salted with the
normalised email) and split with HKDF into an encryption key, which stays on
the device, and an auth key, which the server stores only as a peppered,
salted PBKDF2 hash. Items are AES-256-GCM under a random vault key. That vault
key is wrapped separately by the master password, by a 125-bit Recovery Key,
and by each passkey or phone that can unlock the vault.

The server is a Cloudflare Worker with a D1 (SQLite) database. It adds a second
layer of AES-GCM over the stored wrapped keys and email addresses under a
Worker secret, and never holds anything that could decrypt an item.

Clients:

| Client | Where | Notes |
| --- | --- | --- |
| Web app | `public/js/` | The reference implementation of the crypto |
| Browser extension | `extension/` | Chrome, Firefox and Safari from one source |
| iOS and Android apps | `mobile/` | Capacitor around the web app, plus native unlock and autofill |

## Scope, in priority order

Approximate non-blank lines in brackets.

1. **Client cryptography** (about 1,400): `public/js/crypto.js`,
   `store.js`, `api.js`, `passkey.js`, `platform.js`, `totp.js`. Key
   derivation, wrapping, item encryption and padding, the Recovery Key,
   passkey PRF use, backups.
2. **Server authentication and storage** (about 3,100): everything in
   `src/`. Sign-up, login, sessions and bearer tokens, the origin check and
   CORS, recovery and account reset, TOTP, passkeys, rate limiting, the server
   envelope in `serverkey.ts`, the Stripe webhook signature check, and the
   admin endpoint.
3. **Native unlock and autofill** (about 1,500): the Swift and Java in
   `mobile/plugins/kalm-vault` and `mobile/ios/App/AutoFill`. Keychain and
   Keystore configuration, biometric binding, the shared vault copy, and the
   ports of HKDF and AES-GCM.
4. **Browser extension** (about 1,000): `extension/background.js`,
   `capture.js`, `popup.js`. Message routing between page and extension, fill
   guards, save-on-submit.
5. **Web app UI** (about 3,400): the rest of `public/js/`, for DOM injection
   and anything that could leak plaintext into the page, storage or logs.
6. **Configuration**: `public/_headers` (CSP, HSTS), `wrangler.jsonc`,
   `schema.sql`, `mobile/capacitor.config.json`, the extension manifests
   produced by `scripts/build-extension.mjs`.

Roughly 10,000 lines in all. Most firms will scope this at 10 to 15 person
days for items 1 to 4, with item 5 and 6 as a lighter pass.

## Questions we want answered

- Can the server, someone holding the database, or someone holding
  `SERVER_KEY` recover any item plaintext or any key that opens one?
- Can one account read, alter, or roll back another account's items?
- Can a malicious web page get a password out of the extension, or get it to
  fill on the wrong site?
- Can another app on the phone read the unlock secret or the vault copy?
- Is every IV unique, every tag checked, every comparison constant time?
- Is anything decrypted ever written to disk, logs, or crash reports?

## Known trade-offs

We would rather have these checked than discovered. Each has a reason, and we
will change any of them if the auditors disagree.

1. **Passkeys are not verified as signatures.** The PRF output is treated as
   a secret, like the Recovery Key. The server checks a hash of it and does not
   verify a WebAuthn assertion. See `src/routes/passkeys.ts`.
2. **The phone unlock is a passkey in all but name.** A random 32-byte secret
   in the Keychain or Keystore, registered with the same endpoints.
3. **PBKDF2 rather than Argon2.** Chosen because it is in WebCrypto on every
   platform. The round count is stored per account so it can be raised.
4. **The KDF is salted with the email.** Changing the email re-keys the
   account. See `changeEmail` in `src/routes/account.ts`.
5. **Web-delivered code.** A compromised server could serve a malicious
   client. The extension and apps ship their own copies, which reduces but does
   not remove this for those clients.
6. **Extension and app origins are trusted by name.** The origin check
   accepts `chrome-extension://`, `moz-extension://`,
   `safari-web-extension://` and the two app origins, which all authenticate
   with bearer tokens and never with the cookie. CORS is granted to the app
   origins without credentials.
7. **iOS AutoFill suggestions.** Each login's site and username are given to
   the system's credential identity store so iOS can suggest them. Passwords
   are not.
8. **The vault copy for autofill.** Stored on the phone as the server's
   ciphertext. Its only protection beyond iOS or Android file encryption is the
   biometric-bound secret.
9. **Single server secret.** `SERVER_KEY` has no rotation procedure yet.

## What we provide

- A commit hash to freeze on, and the live instance at kalmpass.net for
  testing with accounts the firm creates. A staging Worker can be set up if
  they prefer not to test production.
- `npm run smoke` and `npm run ext:test`, which exercise the crypto contract
  and the extension end to end.
- Unsigned iOS and Android builds from the Mobile workflow.
- A contact who can answer questions within a working day.

## What we expect back

- A report with findings rated by severity, reproduction steps, and fixes.
- A retest of the fixes, and permission to publish the final report in full,
  which we intend to do.

## Firms to ask

Ask at least three for a quote, sending this brief and a link to the
repository.

- **Cure53** (Berlin). Has audited several password managers, including open
  source ones.
- **Trail of Bits** (New York). Strong on cryptography reviews.
- **NCC Group**. Large, with a dedicated cryptography services team.
- **Radically Open Security** (Amsterdam). A non-profit that often works with
  open source projects.
- **Include Security**, **Doyensec**. Smaller, well regarded application
  security firms.

Funding that can cover part or all of an audit of open source software is
also worth applying for:

- **OSTIF**, the Open Source Technology Improvement Fund, arranges and funds
  audits of open source projects.
- **NLnet Foundation** grants (NGI programmes) have paid for audits through
  Radically Open Security.

Expect somewhere between US$10,000 and US$30,000 for the scope above, depending
on the firm and on how much of the native code is included.
