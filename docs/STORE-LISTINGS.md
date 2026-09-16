# Store listings

Text to paste when submitting KalmPass to each store, plus the answers the
review forms ask for. Keep it in step with the code: if a permission changes,
the justification here has to change with it.

## Browser extension

Build the packages first:

```
npm run ext:build
```

This writes `dist/kalmpass-chrome-<version>.zip` and
`dist/kalmpass-firefox-<version>.zip`.

### Short description (both stores, 132 characters at most)

> Fill and save passwords from your KalmPass vault. Decrypted in the extension, never on our servers.

### Long description

> KalmPass is a zero-knowledge password manager. Your master password never
> leaves your device, and your vault is encrypted before it is stored, so
> nobody at KalmPass can read it.
>
> The extension fills the login for the site you are on, copies usernames,
> passwords and authenticator codes, and can offer to save a login when you
> sign in somewhere new.
>
> It asks for as little as it can. Out of the box it can reach kalmpass.net and
> nothing else, and it runs nothing on the pages you visit until you press
> Fill. Offers to save new logins are off until you switch them on, and your
> browser asks you before they start.
>
> Before filling, it checks that the page is the site the login was saved for
> and that the connection is encrypted, and asks you first if not.
>
> You need a KalmPass account, free at kalmpass.net. The code is open source at
> github.com/KalmPass/KalmPass.

### Chrome Web Store: privacy practices

**Single purpose:** Filling and saving the user's own passwords from their
KalmPass vault.

**Permission justifications:**

| Permission | Why |
| --- | --- |
| `storage` | Keeps the unlocked vault in session memory while the browser is open, and the user's settings. |
| `activeTab` | Lets the extension fill the page the user is looking at, only when they press Fill. |
| `scripting` | Injects the fill function into that page, and registers the save-offer script if the user turns it on. |
| `alarms` | Locks the vault after the idle time the user chose. |
| Host `https://kalmpass.net/*` | The KalmPass API, to sign in and read the encrypted vault. |
| Optional host `https://*/*` | Only requested if the user turns on save offers, so the extension can notice a login being submitted. |

**Remote code:** No. All code is in the package.

**Data usage:** Collects authentication information (the email address and a
key derived from the master password, sent to KalmPass to sign in) and
website content only in the sense of the logins the user chooses to save,
which are encrypted before they leave the device. Not sold, not used for
anything unrelated to the extension, not used for credit decisions.

### Firefox (addons.mozilla.org)

Upload the Firefox zip. It targets Firefox 140 and later, and declares its data
collection in the manifest (authentication information and personally
identifying information, both needed to sign in). The reviewer notes can say:

> The source is the same as the package: no bundler, no minification. It is
> also public at https://github.com/KalmPass/KalmPass under `extension/`,
> built with `npm run ext:build`.

Choose **On this site** to list it publicly, or **On your own** for an
unlisted, self-distributed add-on that Mozilla still signs.

### Safari

Needs a Mac. See "The browser extension" in the README for the converter
command. The listing is part of the iOS or macOS app in App Store Connect.

## Phone apps

### Name and subtitle

- **Name:** KalmPass
- **Subtitle (App Store, 30 characters):** Zero-knowledge password vault
- **Short description (Play, 80 characters):** Your passwords, encrypted on your phone. Unlock with your face or fingerprint.

### Description

> KalmPass keeps your passwords in a vault that only you can open. Everything
> is encrypted on your phone before it is stored, and your master password
> never leaves it, so nobody at KalmPass can read your vault.
>
> - Unlock with Face ID, Touch ID or your fingerprint.
> - Fill passwords into other apps and websites.
> - Generate strong passwords and passphrases.
> - Keep authenticator codes alongside your logins.
> - See weak and reused passwords at a glance.
> - The same vault on the web, in your browser, and on your phone.
>
> If you forget your master password, your Recovery Key gets you back in.
> Nobody else can, including us.
>
> Create a free account in the app or at kalmpass.net.

### App Store review notes

> Sign in with the demo account below. To see autofill, turn on "Unlock with
> this phone" in Settings, then enable KalmPass under Settings, General,
> AutoFill & Passwords.
>
> KalmPass does not sell anything inside the app. Plans are managed on the
> website, and the app does not link to them.

Create a dedicated demo account with a few sample logins for the reviewer, and
put its email and password in the review form rather than here.

### App Store privacy ("nutrition label")

- **Contact info, email address:** collected, linked to the user, used for app
  functionality. Not used for tracking.
- **User content:** the vault is stored, but encrypted on the device with a key
  we never receive. Check Apple's current App Privacy guidance on data you
  cannot read before deciding whether to declare it, and declare it if unsure.
- **Identifiers, device ID:** collected (the random device identifier used to
  count devices), linked to the user, app functionality.
- No tracking, no third-party advertising, no analytics SDKs.

### Google Play data safety

- **Data collected:** email address (account management), and a device
  identifier (app functionality). Both encrypted in transit.
- **Data shared:** none.
- **Encrypted in transit:** yes.
- **Users can request deletion:** yes, from Settings in the app or at
  kalmpass.net.
- **Autofill service declaration:** Play asks apps that use the autofill
  service to confirm it is for password management. It is.

### Encryption export compliance

The apps use standard encryption (AES-GCM, HKDF, PBKDF2) through the
operating system and the browser engine, to protect the user's own data.
Answer the export questions in App Store Connect accordingly; this usually
qualifies for the exemption for authentication and data protection, but
confirm with your own advice before submitting.
