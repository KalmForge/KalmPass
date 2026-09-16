<div align="center">
  <img src="public/icon.svg" width="88" height="88" alt="">
  <h1>KalmPass</h1>
  <p><strong>A password manager that cannot read your passwords.</strong></p>
  <p><a href="https://kalmpass.net">kalmpass.net</a></p>
</div>

---

KalmPass is a zero-knowledge password manager running entirely on Cloudflare, a
Worker, a D1 database, and a static front end served from the edge. Vaults are
encrypted in the browser under a key derived from a master password that is never
transmitted, so the server stores ciphertext it has no means of reading.

It has **no runtime dependencies**. Not one. The whole thing is a few thousand
lines of TypeScript and plain ES modules you can read in an afternoon, which
matters more for a password manager than for almost anything else.

## How the encryption works

```
master password ──PBKDF2-SHA256 × 1,000,000 (salt: email)──▶ master key
                                                                │
                              HKDF "enc" ◀────────────────────┬─┘
                                   │                          │
                                   ▼                    HKDF "auth"
                            encryption key                    │
                                   │                          ▼
                                   │                     auth key ──▶ server
                                   │                  (proves identity;
                                   ▼                   cannot decrypt)
                          wraps the vault key
                                   │
                                   ▼
   vault key ──AES-256-GCM──▶ your items (padded to 256-byte blocks)
       ▲
       └── also wrapped by your Recovery Key (125 bits, saved offline)
```

Two independent secrets open a vault, the master password and the Recovery Key.
KalmPass holds neither. That is the whole design: recovery is possible for the
account holder without anyone escrowing a key on their behalf.

Everything the client sends is then encrypted **again** by the Worker under
`SERVER_KEY`, a secret that never enters the database. Email addresses are stored
as keyed blind indexes plus an encrypted copy, so the database holds no readable
identifier at all.

The full write-up lives at [kalmpass.net/security](https://kalmpass.net/security/)
and in [`public/security/index.html`](public/security/index.html).

## What is in the box

| | |
|---|---|
| **Vault** | Items with username, password, URL, notes, folders, favorites, password history |
| **Authenticator** | TOTP codes generated on-device from seeds stored inside the encrypted blob |
| **Generator** | Passwords and passphrases from `crypto.getRandomValues`, rejection-sampled to remove modulo bias, with honest entropy figures |
| **Health** | Weak, reused and stale passwords; breach checking via HIBP k-anonymity (Pro) |
| **Recovery** | Recovery Key / Emergency Kit, plus an email-verified account reset for people who lose both |
| **Accounts** | Signup, email confirmation, optional TOTP two-factor with backup codes, device list, activity log |
| **Billing** | Stripe Checkout and customer portal, subscription webhooks, server-enforced plan quotas |
| **Portability** | Encrypted JSON backups, CSV import from LastPass / Bitwarden / 1Password / Chrome |

## The browser extension

`extension/` is one Manifest V3 extension that builds for Chrome (and Edge,
Brave, Opera), Firefox and Safari. Only the manifest differs between them.

```
npm run ext:build   # dist/extension/{chrome,firefox,safari} and store zips
npm run ext:lint    # Mozilla's linter over the Firefox build
npm run ext:test    # the real background worker against the live server
```

To try it before the store listings exist:

- **Chrome, Edge, Brave:** open `chrome://extensions`, turn on Developer mode,
  **Load unpacked**, and choose `extension/` (or `dist/extension/chrome`).
- **Firefox 140 or later:** open `about:debugging#/runtime/this-firefox`,
  **Load Temporary Add-on**, and pick `dist/extension/firefox/manifest.json`.
  It lasts until Firefox restarts. For a permanent install, upload
  `dist/kalmpass-firefox-<version>.zip` to addons.mozilla.org, either listed or
  as an unlisted self-distributed add-on, which Mozilla signs automatically.
- **Safari:** needs a Mac with Xcode. Run
  `xcrun safari-web-extension-converter dist/extension/safari --app-name KalmPass --bundle-identifier net.kalmpass.safari --no-open`,
  open the generated project, set your team under Signing, and run it. Then
  enable KalmPass in Safari's Settings, Extensions. Shipping it to other people
  goes through the App Store and an Apple Developer account.

Out of the box it asks for `storage`, `activeTab`, `scripting` and `alarms`,
plus host access to `kalmpass.net` alone. There is no `<all_urls>`, so the
extension runs no code on any page until you press Fill.

**Save offers are opt in.** Ticking "Offer to save logins" in the popup asks
the browser for access to `https://*/*` (an optional permission) and only then
registers `capture.js`. That script watches for a login being sent and passes
the username and password to the background worker. It never runs on
kalmpass.net, never on plain http, and never inside frames. The worker keeps
the unsaved login in session memory for ten minutes at most and shows a `+` on
the toolbar icon; the offer itself appears in the popup, where a page cannot
draw a fake one. Messages from a page can reach exactly one handler, the one
that suggests a login, so a hostile page cannot ask for secrets.

**Filling warns first** when the page is not the site the login was saved for,
or is not encrypted, and fills only after a second click.

Keys live only in the background worker, held in `chrome.storage.session`,
which is memory backed and cleared when the browser quits. The popup never receives a
secret unless you ask to copy that particular one, and filling happens in the
worker so a password reaches the page without passing through the popup at all.

The extension authenticates with a bearer token rather than the session cookie,
because a `SameSite=Strict` cookie will not travel from an extension origin.
The server accepts `chrome-extension://`, `moz-extension://` and
`safari-web-extension://` origins for that reason; a web page cannot claim
any of them. `npm run smoke` and `npm run ext:test` both sign in that way.

`extension/lib/` holds copies of the crypto modules, since an extension cannot
import from the website. `npm run lint:libs` fails the build if they drift.

## The phone apps

`mobile/` is a Capacitor 8 project that packages the web app for iOS and
Android, plus the parts a WebView cannot do:

- **Unlock with Face ID, Touch ID or a fingerprint.** `mobile/plugins/kalm-vault`
  keeps a random 32-byte secret in the Keychain or the Android Keystore, bound
  to strong biometrics and invalidated when enrolment changes. The server
  knows it as a passkey, so no new endpoints were needed.
- **Autofill in other apps and browsers.** An iOS AutoFill credential provider
  extension (`mobile/ios/App/AutoFill`) and an Android autofill service read
  the vault as the server stores it, ask for a biometric check, and decrypt in
  memory with small Swift and Java ports of the web app's HKDF and AES-GCM.
- **No in-app purchases.** The stores require their own billing for anything
  sold in an app, so the apps show the plan and do not sell one.

The apps talk to `https://kalmpass.net` from their own origins
(`capacitor://app.kalmpass.net` on iOS, `https://app.kalmpass.net` on
Android). The Worker grants those two CORS without credentials, and the apps
authenticate with a bearer token held in memory.

```
cd mobile
npm ci
npm run android     # copies the web app, syncs, opens Android Studio
npm run ios         # the same for Xcode, on a Mac
```

On a Mac, once, before the first iOS build:

```
ruby scripts/add-autofill-target.rb   # adds the AutoFill extension target
```

Then in Xcode, set your team on both targets, and add the **App Groups**
(`group.net.kalmpass`), **Keychain Sharing** (`net.kalmpass.shared`) and
**AutoFill Credential Provider** capabilities to both. The entitlements files
already name them; Xcode needs your team to register them.

The **Mobile** workflow builds both apps unsigned on every change, so native
compile errors show up in CI. Store builds need signing:

- **Android:** create an upload keystore, add a `release` signing config, and
  `./gradlew bundleRelease` for Google Play.
- **iOS:** an Apple Developer account, then Archive in Xcode and upload with
  the Organizer or Transporter.

`npm run icons` in the repository root redraws the app icons and launch
screens from the mark.

## Repository layout

```
src/                  the Worker, no runtime dependencies
mobile/               the iOS and Android apps (Capacitor, plus native unlock and autofill)
docs/AUDIT.md         the brief to send to security audit firms
  index.ts            router; the only entry point
  crypto.ts           hashing, random, constant-time compare
  serverkey.ts        the server envelope (layer 2) and blind indexes
  sessions.ts         session tokens, scopes, device limits
  throttle.ts         login and recovery rate limiting
  accounts.ts         user row, plan and verification checks
  audit.ts            the account's own security log
  email.ts            transactional mail
  totp.ts             RFC 6238, for the second factor on login
  plans.ts            what Free and Pro allow
  routes/             account, items, billing, tools

public/               static, served from the edge
  index.html          marketing site
  security/ terms/ privacy/
  app/index.html      the vault
  js/crypto.js        client-side cryptography, the part that matters
  js/store.js         vault state; nothing is ever written to disk
  js/*.js             ui, generator, totp, health, settings
  _headers            CSP and the rest of the security headers

schema.sql            D1 schema, annotated
```

## Running it locally

```bash
npm install
npm run db:init:local
npm run dev
```

You will need a `.dev.vars` containing at least:

```
SERVER_KEY="<32 random bytes, base64>"
```

Generate one with:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"
```

## Deploying

```bash
npm run db:init      # once, against the remote D1 database
npx wrangler secret put SERVER_KEY
npm run deploy
```

> **`SERVER_KEY` is not recoverable.** Every row in D1 is encrypted under a key
> derived from it. Lose it and the database becomes unreadable even to the people
> holding the right master passwords. Back it up somewhere other than this repo.
>
> It is *not* a backdoor: holding it still does not decrypt a vault, because the
> client layer sits underneath and needs a master password nobody else has.

### Secrets

| Name | Required | Purpose |
|---|---|---|
| `SERVER_KEY` | yes | Derives the envelope key, the hashing pepper and the email blind-index key |
| `SIGNUP_TOKEN` | no | Invite code gating registration. Delete it to open signups publicly |
| `STRIPE_SECRET_KEY` | for billing | Stripe API key |
| `STRIPE_WEBHOOK_SECRET` | for billing | Verifies webhook signatures |
| `STRIPE_PRICE_ID` | for billing | The Pro subscription price |

Non-secret settings (`APP_URL`, `MAIL_FROM`, `ALLOW_SIGNUP`) live in
`wrangler.jsonc`.

## Launch checklist

- [x] **Email sending.** Done. kalmpass.net is onboarded, and Cloudflare wrote
      the SPF, DKIM, DMARC and bounce MX records itself. Note that Email Sending
      needs the Workers Paid plan; on the free plan the dashboard offers no way
      to onboard a domain and the API answers Unauthorized, which reads as a
      permissions problem but is a billing one.
- [ ] **Stripe.** Create a Pro price, set the three `STRIPE_*` secrets with
      `npm run stripe:secrets`, and point a webhook at
      `https://kalmpass.net/api/billing/webhook` for
      `checkout.session.completed`, `customer.subscription.*` and
      `invoice.payment_failed`.

      Test and live are separate worlds. The product, the price, the keys and
      the webhook all exist twice over and none of it carries across. Mixing a
      live key with a test webhook secret fails silently: the customer pays and
      the plan never changes. The admin page shows which mode the keys are in,
      so check it after any switch.
- [x] **Open signups.** Done. Re-close them at any time by setting SIGNUP_TOKEN
      again, or ALLOW_SIGNUP to "false" in wrangler.jsonc.
- [ ] **Legal.** `public/terms/` and `public/privacy/` are drafts with bracketed
      placeholders. Have a solicitor review them before taking payment.
- [ ] **Price.** The landing page, `PRO_PRICE` in wrangler.jsonc, and the Stripe
      price must all agree. `npm run lint:libs` checks the first two; only you
      can check the third. `npm run lint:libs` also checks that the currency
      symbol on the page matches `PRO_CURRENCY`.

## What this does not protect against

Stated plainly, because a security product that only lists its strengths is not
being straight with you:

- **A compromised device.** Malware or a browser extension with page access can
  read a vault while it is unlocked.
- **A weak master password.** A million PBKDF2 rounds multiplies an attacker's
  cost; it does not rescue a guessable password.
- **A malicious server operator.** We cannot decrypt what has already been sent,
  but in principle we could serve altered JavaScript in future. That risk is
  inherent to every web-delivered password manager. It is why this code ships no
  third-party dependencies at all: there is no CDN, no analytics and no package
  that could be compromised to change what runs in the browser. Making the
  repository public would strengthen this further, by letting the served page be
  checked against the source.
- **Losing both the master password and the Recovery Key.** The data is then gone
  for good. That is the direct cost of nobody else holding a key.

## Security reports

Please email [security@kalmpass.net](mailto:security@kalmpass.net) before
disclosing publicly. Reports made in good faith will never be met with legal
threats.

## Licence

AGPL-3.0. See [LICENSE](LICENSE).

The source is published so that anyone trusting KalmPass with their passwords
can check it rather than take our word for it. Self-host it, fork it, study it.
If you offer a modified version to other people as a service, publish your
changes too.
