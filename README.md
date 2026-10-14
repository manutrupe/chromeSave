# ChromeSave – Fingerprint & Face Lock for Chrome

A Chrome extension (Windows and macOS) that locks the websites you choose, such as
your email, behind your computer's built-in biometrics:

| OS      | What you use to unlock                                              |
| ------- | ------------------------------------------------------------------- |
| Windows | **Windows Hello**: fingerprint, face recognition, or your Hello PIN |
| macOS   | **Touch ID**, or your Mac password when Touch ID isn't available    |

> Macs don't have Face ID; on a Mac the biometric option is Touch ID.

## Features

- **Choose your sites.** Add any site (`mail.google.com`, `outlook.live.com`, …) or
  use one-click presets for Gmail, Outlook, Yahoo Mail, Proton Mail and iCloud Mail.
  Subdomains are included, and you can protect only part of a site
  (`icloud.com/mail`).
- **Locked before it loads.** A protected page is swapped for a lock screen before
  the request leaves the browser, so the page never appears.
- **Unlock with fingerprint / face.** After verification the site stays open for a
  period you choose (1 minute to 4 hours, or until Chrome is closed). Other tabs
  waiting on the same site unlock too.
- **Turning it off needs your fingerprint / face too.** Disabling protection,
  removing sites, or changing any setting asks for verification first.
- **Extensions page guard (optional, on by default).** Opening `chrome://extensions`
  also asks for verification, which makes it harder to switch ChromeSave off or
  remove it from there.
- **Re-locks automatically** when Chrome restarts, when your computer locks or
  sleeps, when the unlock period ends, or when you click "Lock all sites now".

## Install (Windows and Mac)

1. Download this repository (green **Code** button › *Download ZIP*) and unzip it,
   or `git clone` it.
2. Open Chrome and go to `chrome://extensions`.
3. Turn on **Developer mode** (top-right).
4. Click **Load unpacked** and select the **`extension`** folder.
5. The settings page opens. Click **Set up now** and confirm with your fingerprint,
   face, or PIN when Windows Hello / Touch ID asks.
6. Add the sites you want to protect, for example click **+ Gmail**.

Requirements: Chrome 122 or newer (Edge, Brave and other Chromium browsers also
work). Windows Hello or Touch ID must be set up on the computer:

- **Windows:** Settings › Accounts › Sign-in options › Windows Hello.
- **Mac:** System Settings › Touch ID & Password.

## Using it

- **Toolbar button:** shows whether protection is on, protects the current site,
  locks the current site or all sites now, and opens the settings.
- **Turn protection off:** toolbar › *Turn off protection…* (or open the settings),
  verify, then switch **Protection** off.
- **New computer, or Windows Hello / Touch ID was reset:** settings › *Register again*.
  If you can no longer verify at all, remove the extension and install it again.
  This wipes its settings.

## How it works

```
navigate to mail.google.com
        │
        ▼
declarativeNetRequest redirect rule ──► lock.html#https://mail.google.com/…
                                              │  navigator.credentials.get()
                                              │  (Windows Hello / Touch ID,
                                              │   userVerification: required)
                                              ▼
                     service worker verifies the signature with the public key
                     saved at setup, then adds a session "allow" rule and
                     sends the tab back to the original URL
```

- Setup creates a **WebAuthn platform credential**. The private key stays in
  Windows Hello / the Mac's Secure Enclave; the extension only stores the public key.
- Each unlock signs a fresh, single-use challenge. The service worker checks the
  challenge, the extension origin, the "user verified" flag, the signature counter
  and the signature (ES256 or RS256) before unlocking anything. A page can't just
  claim it was verified.
- Unlocks are **session** rules, so Chrome deletes them on restart and every site
  starts out locked.
- Settings changes need a short-lived token (10 minutes, extended while you use
  the page), issued only after a verified fingerprint / face check.

## Limits

An extension runs inside the browser, so it can't stop someone who controls the
computer itself:

- Chrome lets anyone remove an extension from the toolbar menu (*Remove from
  Chrome…*) or start Chrome with extensions turned off. The extensions-page guard
  makes this harder but can't fully prevent it. To enforce the extension, install
  it through Chrome enterprise policy (`ExtensionInstallForcelist`).
- Other browsers or Chrome profiles on the same computer aren't protected.
- Sign-in sessions are not touched: unlocking shows the page with your existing
  login. ChromeSave adds a lock in front of the page; it doesn't replace your
  email password or 2-step verification.
- Pages already open and unlocked keep running until the unlock period ends or you
  lock them. At that point the tab is sent back to the lock screen.

## Development

```bash
npm install          # only needed for the end-to-end test (Playwright)
npm test             # unit tests: site matching and WebAuthn signature checks
npm run test:e2e     # loads the extension in Chromium with a virtual authenticator
npm run package      # creates chromesave.zip for the Chrome Web Store
```

```
extension/
  manifest.json
  background.js            service worker: rules, verification, settings
  lib/sites.js             site pattern parsing and matching
  lib/webauthn-verify.js   registration and assertion verification
  lib/client.js            page-side WebAuthn calls and messaging
  lib/encoding.js          base64url helpers
  pages/                   lock screen, settings page, toolbar popup
  icons/
tests/
```
