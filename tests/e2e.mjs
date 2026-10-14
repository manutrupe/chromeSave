// End-to-end test: loads the unpacked extension into Chromium and drives it
// with a CDP virtual platform authenticator standing in for Windows Hello /
// Touch ID. A local HTTP server plays the "email" site, reached through a
// host-resolver rule so real hostnames can be used.
//
//   npm run test:e2e

import { chromium } from 'playwright';
import http from 'node:http';
import path from 'node:path';
import os from 'node:os';
import fs from 'node:fs';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';

const EXT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../extension');

const hits = [];
const server = http.createServer((req, res) => {
  hits.push(req.headers.host + req.url);
  res.setHeader('content-type', 'text/html');
  res.end(`<title>site</title><h1 id="content">Content of ${req.headers.host}${req.url}</h1>`);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const PORT = server.address().port;
const MAIL = `http://mail.example.test:${PORT}/inbox`;
const OTHER = `http://news.example.test:${PORT}/`;

const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'chromesave-e2e-'));
const context = await chromium.launchPersistentContext(userDataDir, {
  channel: 'chromium',
  headless: true,
  args: [
    `--disable-extensions-except=${EXT}`,
    `--load-extension=${EXT}`,
    '--host-resolver-rules=MAP *.example.test 127.0.0.1',
  ],
});

let step = 0;
const log = (msg) => console.log(`  ${++step}. ${msg}`);

try {
  let [worker] = context.serviceWorkers();
  worker ??= await context.waitForEvent('serviceworker');
  const extId = new URL(worker.url()).host;
  const OPTIONS = `chrome-extension://${extId}/pages/options.html`;
  const LOCK = `chrome-extension://${extId}/pages/lock.html`;

  // Use a single tab: virtual authenticators belong to a tab.
  const page = await context.newPage();
  for (const p of context.pages()) if (p !== page) await p.close();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: true,
      automaticPresenceSimulation: true,
    },
  });
  const setVerified = (isUserVerified) =>
    cdp.send('WebAuthn.setUserVerified', { authenticatorId, isUserVerified });
  const state = () => page.evaluate(() => chrome.runtime.sendMessage({ type: 'getState' }));

  // --- setup -----------------------------------------------------------------
  await page.goto(OPTIONS);
  await page.locator('#setup').waitFor();
  await page.click('#register');
  await page.locator('#manage').waitFor();
  let s = await state();
  assert.ok(s.registered, 'credential registered');
  assert.ok(s.settings.enabled, 'protection on after setup');
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  log(`registered platform credential (rpId used: ${credentials[0].rpId}, stored override: ${s.rpId ?? 'none'})`);

  await page.fill('#add-input', 'mail.example.test');
  await page.click('#add-form button');
  await page.locator('#sites li .name', { hasText: 'mail.example.test' }).waitFor();
  log('added mail.example.test as a protected site');

  // --- locked navigation is intercepted before any request -------------------
  await setVerified(false);
  await page.goto(MAIL).catch(() => {});
  await page.waitForURL((u) => u.href.startsWith(LOCK));
  assert.equal(page.url(), `${LOCK}#${MAIL}`);
  await page.locator('#error').filter({ hasText: /./ }).waitFor();
  assert.equal(hits.filter((h) => h.startsWith('mail.')).length, 0, 'no request reached the site');
  log('protected site shows lock screen; failed verification keeps it locked; site never contacted');

  // --- unprotected sites are untouched -------------------------------------
  await page.goto(OTHER);
  assert.equal(page.url(), OTHER);
  log('unprotected site loads normally');

  // --- unlock with the authenticator ------------------------------------------
  await setVerified(true);
  await page.goto(MAIL).catch(() => {});
  await page.waitForURL(MAIL);
  await page.locator('#content').waitFor();
  log('fingerprint/face verification unlocks and continues to the page');

  // Still unlocked within the window.
  await page.goto(OTHER);
  await page.goto(MAIL);
  assert.equal(page.url(), MAIL);
  log('site stays unlocked for the configured period');

  // --- lock all re-locks open tabs ---------------------------------------------
  await setVerified(false);
  const helper = await context.newPage();
  await helper.goto(OPTIONS);
  await helper.evaluate(() => chrome.runtime.sendMessage({ type: 'lockAll' }));
  await helper.close();
  await page.waitForURL((u) => u.href.startsWith(LOCK));
  log('"Lock all" sends open protected tabs back to the lock screen');

  // --- changing settings / disabling needs verification ------------------------
  await page.goto(OPTIONS);
  await page.locator('#locked').waitFor();
  await page.click('#verify');
  await page.locator('#error').filter({ hasText: /./ }).waitFor();
  assert.ok(await page.locator('#manage').isHidden(), 'settings stay locked on failed verification');
  const forged = await page.evaluate(() =>
    chrome.runtime.sendMessage({ type: 'updateSettings', token: 'forged', patch: { enabled: false } }),
  );
  assert.equal(forged.ok, false);
  assert.equal(forged.code, 'auth_required');
  const fakeUnlock = await page.evaluate((url) =>
    chrome.runtime.sendMessage({
      type: 'unlock',
      url,
      assertion: { id: 'x', clientDataJSON: 'e30', authenticatorData: '', signature: '' },
    }),
  MAIL);
  assert.equal(fakeUnlock.ok, false);
  log('disabling protection or forging an unlock without verification is refused');

  // --- guard for the browser's extensions page ---------------------------------
  await page.goto('chrome://extensions/').catch(() => {});
  await page.waitForURL((u) => u.href.startsWith(LOCK));
  assert.match(await page.locator('#title').textContent(), /Extension settings are protected/);
  await setVerified(true);
  await page.click('#unlock');
  await page.waitForURL((u) => u.href.startsWith('chrome://extensions'));
  log('chrome://extensions requires verification, then opens');

  const openSettings = async () => {
    await page.goto(OPTIONS);
    await page.click('#verify');
    await page.locator('#manage').waitFor();
  };
  const onLockScreen = () => page.waitForURL((u) => u.href.startsWith(LOCK));

  // --- ask mode: every time the page is opened ---------------------------------
  await openSettings();
  await page.selectOption('#ask-mode', 'open');
  await page.locator('#ask-mode-hint', { hasText: 'Each tab asks separately' }).waitFor();
  assert.ok(await page.locator('#unlock-minutes-field').isHidden(), 'duration hidden in per-open mode');
  await page.goto(MAIL).catch(() => {});
  await page.waitForURL(MAIL);
  await page.locator('#content').waitFor();
  await page.evaluate(() => history.pushState({}, '', '/inbox/thread-1'));
  await page.waitForTimeout(500);
  assert.match(page.url(), /\/inbox\/thread-1$/, 'in-page navigation does not re-lock');
  await setVerified(false);
  await page.reload().catch(() => {});
  await onLockScreen();
  log('"every page open": reloading asks again (in-page navigation does not)');

  const second = await context.newPage();
  await second.goto(MAIL).catch(() => {});
  await second.waitForURL((u) => u.href.startsWith(LOCK));
  await second.close();
  await page.bringToFront();
  log('"every page open": the same site in another tab asks separately');

  await setVerified(true);
  await page.click('#unlock');
  await page.waitForURL((u) => u.href.startsWith(MAIL.replace('/inbox', '')));
  await page.goto(OTHER);
  await setVerified(false);
  await page.goto(MAIL).catch(() => {});
  await onLockScreen();
  log('"every page open": leaving the site and coming back asks again');

  // --- per-site override: every tab switch -------------------------------------
  await setVerified(true);
  await openSettings();
  await page.locator('#sites li select').selectOption('switch');
  await page.waitForFunction(() => {
    const sel = document.querySelector('#sites li select');
    return sel && sel.value === 'switch';
  });
  s = await state();
  assert.equal(s.settings.sites[0].askMode, 'switch');
  assert.equal(s.settings.askMode, 'open');
  await page.goto(MAIL).catch(() => {});
  await page.waitForURL(MAIL);
  await page.locator('#content').waitFor();
  const other = await context.newPage();
  await other.goto(OTHER);
  await other.bringToFront();
  await onLockScreen();
  log('"every tab switch" (per-site override): switching away locks the tab');

  await page.bringToFront();
  await page.waitForURL(MAIL);
  await page.locator('#content').waitFor();
  await other.close();
  log('"every tab switch": switching back prompts for verification, then reopens the page');

  // --- turn protection off with verification -----------------------------------
  await page.goto(OPTIONS);
  await page.click('#verify');
  await page.locator('#manage').waitFor();
  await page.click('.switch');
  await page.locator('#protection-text', { hasText: 'OFF' }).waitFor();
  s = await state();
  assert.equal(s.settings.enabled, false);
  await page.goto(MAIL);
  assert.equal(page.url(), MAIL);
  log('verified user can turn protection off; site then opens without a prompt');

  console.log('\nE2E PASSED');
} catch (err) {
  console.error('\nE2E FAILED:', err);
  process.exitCode = 1;
} finally {
  await context.close();
  server.close();
  fs.rmSync(userDataDir, { recursive: true, force: true });
}
