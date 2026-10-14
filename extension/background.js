// ChromeSave service worker.
//
// Protected sites are enforced with declarativeNetRequest:
//   * a dynamic "redirect" rule per site sends top-level navigations to the
//     lock page (dynamic rules survive browser restarts), and
//   * a session "allow" rule with higher priority is added while a site is
//     unlocked (session rules are wiped when Chrome closes, so everything is
//     locked again on the next start).
//
// When to ask is configurable globally and per site ("ask mode"):
//   * "session": one check unlocks the site in every tab for a set time;
//   * "open":    each page load needs a check. The unlock belongs to one tab
//                and is used up once the page has loaded, so a reload, a new
//                tab or coming back to the site locks it again;
//   * "switch":  like "open", and the tab also locks when you leave it.
// Every unlock and every settings change requires a WebAuthn assertion from
// the platform authenticator registered at setup, verified here.

import { findSite, formatPattern, parsePattern, patternToRegex } from './lib/sites.js';
import { randomB64u } from './lib/encoding.js';
import { verifyAssertion, verifyRegistration } from './lib/webauthn-verify.js';

const LOCK_URL = chrome.runtime.getURL('pages/lock.html');
const ORIGIN = new URL(chrome.runtime.getURL('')).origin;
const EXTENSIONS_PAGE_RE = /^(chrome|edge|brave|opera|vivaldi):\/\/extensions\b/i;

const CHALLENGE_TTL_MS = 2 * 60 * 1000;
const ADMIN_TTL_MS = 10 * 60 * 1000;
const EXTENSIONS_PAGE_TTL_MS = 5 * 60 * 1000;
const SESSION_RULE_OFFSET = 10000;
const TAB_RULE_OFFSET = 20000;
// How long a per-tab unlock waits for its page to load before it lapses.
const TAB_PENDING_TTL_MS = 2 * 60 * 1000;
const ASK_MODES = ['session', 'open', 'switch'];
const MAX_SITES = 500;
const UNLOCK_CHOICES = [0, 1, 5, 15, 30, 60, 240];

const DEFAULT_SETTINGS = {
  enabled: false,
  sites: [],
  askMode: 'session',
  unlockMinutes: 15,
  lockOnSystemLock: true,
  guardExtensionsPage: true,
};

// ---------------------------------------------------------------- state ----

async function getSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...settings };
}

async function getCredential() {
  const { credential } = await chrome.storage.local.get('credential');
  return credential || null;
}

async function getSession() {
  const s = await chrome.storage.session.get([
    'unlocked',
    'tabUnlocks',
    'admin',
    'challenges',
    'extensionsUntil',
  ]);
  return {
    unlocked: s.unlocked || {},
    tabUnlocks: s.tabUnlocks || {},
    admin: s.admin || null,
    challenges: s.challenges || {},
    extensionsUntil: s.extensionsUntil || 0,
  };
}

/** Drops expired unlocks; returns the live map of siteId -> expiry (0 = until restart). */
async function getUnlocked() {
  const { unlocked } = await getSession();
  const now = Date.now();
  const live = Object.fromEntries(
    Object.entries(unlocked).filter(([, until]) => until === 0 || until > now),
  );
  if (Object.keys(live).length !== Object.keys(unlocked).length) {
    await chrome.storage.session.set({ unlocked: live });
  }
  return live;
}

/**
 * Per-tab unlocks: tabId -> { siteId, pendingUntil }. While `pendingUntil` is
 * set, a tab-scoped DNR rule lets the next page load through; once the page
 * has loaded it is cleared and the unlock lasts as long as that page stays
 * open in the tab.
 */
async function getTabUnlocks() {
  const { tabUnlocks } = await getSession();
  const now = Date.now();
  const live = Object.fromEntries(
    Object.entries(tabUnlocks).filter(([, g]) => !g.pendingUntil || g.pendingUntil > now),
  );
  if (Object.keys(live).length !== Object.keys(tabUnlocks).length) {
    await chrome.storage.session.set({ tabUnlocks: live });
  }
  return live;
}

function modeFor(site, settings) {
  return ASK_MODES.includes(site.askMode) ? site.askMode : settings.askMode;
}

function isActive(settings, credential) {
  return Boolean(settings.enabled && credential && settings.sites.length);
}

// ---------------------------------------------------------------- rules ----

let syncChain = Promise.resolve();

/** Rebuilds DNR rules from current state. Calls are serialised. */
function syncRules() {
  syncChain = syncChain.then(doSyncRules, doSyncRules);
  return syncChain;
}

async function doSyncRules() {
  const [settings, credential, unlocked, tabUnlocks] = await Promise.all([
    getSettings(),
    getCredential(),
    getUnlocked(),
    getTabUnlocks(),
  ]);
  const active = isActive(settings, credential);
  const sites = active ? settings.sites : [];

  const redirectRules = sites.map((site, i) => ({
    id: i + 1,
    priority: 1,
    action: {
      type: 'redirect',
      redirect: { regexSubstitution: LOCK_URL + '#\\0' },
    },
    condition: { regexFilter: patternToRegex(site), resourceTypes: ['main_frame'] },
  }));
  const allowRules = sites.flatMap((site, i) =>
    modeFor(site, settings) === 'session' && site.id in unlocked
      ? [
          {
            id: SESSION_RULE_OFFSET + i + 1,
            priority: 2,
            action: { type: 'allow' },
            condition: { regexFilter: patternToRegex(site), resourceTypes: ['main_frame'] },
          },
        ]
      : [],
  );
  Object.entries(tabUnlocks).forEach(([tabId, grant], i) => {
    const site = sites.find((s) => s.id === grant.siteId);
    if (!grant.pendingUntil || !site || modeFor(site, settings) === 'session') return;
    allowRules.push({
      id: TAB_RULE_OFFSET + i + 1,
      priority: 3,
      action: { type: 'allow' },
      condition: {
        regexFilter: patternToRegex(site),
        resourceTypes: ['main_frame'],
        tabIds: [Number(tabId)],
      },
    });
  });

  const [oldDynamic, oldSession] = await Promise.all([
    chrome.declarativeNetRequest.getDynamicRules(),
    chrome.declarativeNetRequest.getSessionRules(),
  ]);
  // Allow rules go in first and come out last, so a site never flashes
  // open or locked by accident between the two updates.
  await chrome.declarativeNetRequest.updateSessionRules({
    removeRuleIds: oldSession.map((r) => r.id),
    addRules: allowRules,
  });
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: oldDynamic.map((r) => r.id),
    addRules: redirectRules,
  });

  await scheduleRelock(unlocked, tabUnlocks);
}

async function scheduleRelock(unlocked, tabUnlocks = {}) {
  const expiries = Object.values(unlocked).filter((t) => t > 0);
  for (const g of Object.values(tabUnlocks)) if (g.pendingUntil) expiries.push(g.pendingUntil);
  const { extensionsUntil } = await getSession();
  if (extensionsUntil > Date.now()) expiries.push(extensionsUntil);
  await chrome.alarms.clear('relock');
  if (expiries.length) {
    // Chrome enforces a 30 s minimum delay for alarms.
    chrome.alarms.create('relock', { when: Math.max(Math.min(...expiries), Date.now() + 30000) });
  }
}

// ------------------------------------------------------------- locking -----

function lockPageFor(url) {
  return LOCK_URL + '#' + url;
}

/** Returns the lock-page URL a tab should be sent to, or null if it may stay. */
async function lockTargetFor(url, tabId) {
  if (!url || url.startsWith(LOCK_URL)) return null;
  const [settings, credential] = await Promise.all([getSettings(), getCredential()]);
  if (!credential) return null;

  if (EXTENSIONS_PAGE_RE.test(url)) {
    if (!settings.guardExtensionsPage) return null;
    const { extensionsUntil } = await getSession();
    return extensionsUntil > Date.now() ? null : lockPageFor(url);
  }

  if (!isActive(settings, credential)) return null;
  const site = findSite(settings.sites, url);
  if (!site) return null;
  if (modeFor(site, settings) === 'session') {
    const unlocked = await getUnlocked();
    return site.id in unlocked ? null : lockPageFor(url);
  }
  const tabUnlocks = await getTabUnlocks();
  return tabUnlocks[tabId]?.siteId === site.id ? null : lockPageFor(url);
}

/** Sends every open tab showing a locked page to the lock screen. */
async function sweepTabs() {
  const tabs = await chrome.tabs.query({});
  await Promise.all(
    tabs.map(async (tab) => {
      const target = await lockTargetFor(tab.pendingUrl || tab.url, tab.id);
      if (target) await chrome.tabs.update(tab.id, { url: target }).catch(() => {});
    }),
  );
}

async function lockAll() {
  await chrome.storage.session.set({ unlocked: {}, tabUnlocks: {}, admin: null, extensionsUntil: 0 });
  await syncRules();
  await sweepTabs();
}

// --------------------------------------------------------- challenges ------

async function issueChallenge(purpose) {
  const { challenges } = await getSession();
  const now = Date.now();
  for (const [k, v] of Object.entries(challenges)) if (v.exp < now) delete challenges[k];
  const challenge = randomB64u(32);
  challenges[challenge] = { purpose, exp: now + CHALLENGE_TTL_MS };
  await chrome.storage.session.set({ challenges });
  return challenge;
}

/** Consumes a challenge; throws unless it was issued for `purpose` and is fresh. */
async function consumeChallenge(challenge, purpose) {
  const { challenges } = await getSession();
  const entry = challenges[challenge];
  delete challenges[challenge];
  await chrome.storage.session.set({ challenges });
  if (!entry || entry.purpose !== purpose || entry.exp < Date.now()) {
    throw new Error('Expired or unknown challenge, please try again');
  }
}

function challengeFromClientData(b64) {
  try {
    const json = new TextDecoder().decode(
      Uint8Array.from(atob(b64.replace(/-/g, '+').replace(/_/g, '/')), (c) => c.charCodeAt(0)),
    );
    return JSON.parse(json).challenge;
  } catch {
    throw new Error('Malformed clientDataJSON');
  }
}

async function checkAssertion(assertion, purpose) {
  const credential = await getCredential();
  if (!credential) throw new Error('No fingerprint / face credential is registered yet');
  const challenge = challengeFromClientData(assertion.clientDataJSON);
  await consumeChallenge(challenge, purpose);
  const signCount = await verifyAssertion(assertion, credential, { challenge, origin: ORIGIN });
  await chrome.storage.local.set({ credential: { ...credential, signCount } });
}

// --------------------------------------------------------- admin token -----

async function grantAdmin() {
  const token = randomB64u(32);
  await chrome.storage.session.set({ admin: { token, exp: Date.now() + ADMIN_TTL_MS } });
  return token;
}

class AuthRequired extends Error {
  code = 'auth_required';
}

async function requireAdmin(token) {
  const { admin } = await getSession();
  if (!admin || !token || admin.token !== token || admin.exp < Date.now()) {
    throw new AuthRequired('Please verify with your fingerprint or face to change settings');
  }
  // Sliding expiry while the settings page is in use.
  await chrome.storage.session.set({ admin: { token, exp: Date.now() + ADMIN_TTL_MS } });
}

// ------------------------------------------------------------- settings ----

function sanitizeSites(input, previous) {
  if (!Array.isArray(input)) throw new Error('Invalid site list');
  if (input.length > MAX_SITES) throw new Error(`At most ${MAX_SITES} sites are supported`);
  const byPattern = new Map(previous.map((s) => [formatPattern(s), s]));
  const seen = new Set();
  const out = [];
  for (const raw of input) {
    const parsed = parsePattern(typeof raw === 'string' ? raw : raw?.pattern);
    if (!parsed) throw new Error(`"${typeof raw === 'string' ? raw : raw?.pattern}" is not a valid site`);
    const key = formatPattern(parsed);
    if (seen.has(key)) continue;
    seen.add(key);
    const label = typeof raw === 'object' && typeof raw.label === 'string' ? raw.label.slice(0, 80) : '';
    // Keep ids stable so existing unlocks survive unrelated edits.
    const id = byPattern.get(key)?.id || randomB64u(9);
    const askMode = ASK_MODES.includes(raw?.askMode) ? raw.askMode : 'default';
    out.push({ id, ...parsed, label, askMode });
  }
  return out;
}

async function updateSettings(patch) {
  const settings = await getSettings();
  const next = { ...settings };
  if ('enabled' in patch) next.enabled = Boolean(patch.enabled);
  if ('lockOnSystemLock' in patch) next.lockOnSystemLock = Boolean(patch.lockOnSystemLock);
  if ('guardExtensionsPage' in patch) next.guardExtensionsPage = Boolean(patch.guardExtensionsPage);
  if ('askMode' in patch) {
    if (!ASK_MODES.includes(patch.askMode)) throw new Error('Invalid ask mode');
    next.askMode = patch.askMode;
  }
  if ('unlockMinutes' in patch) {
    const m = Number(patch.unlockMinutes);
    if (!UNLOCK_CHOICES.includes(m)) throw new Error('Invalid unlock duration');
    next.unlockMinutes = m;
  }
  if ('sites' in patch) next.sites = sanitizeSites(patch.sites, settings.sites);

  await chrome.storage.local.set({ settings: next });
  // Unlocks for removed sites are dropped.
  const unlocked = await getUnlocked();
  const ids = new Set(next.sites.map((s) => s.id));
  const kept = Object.fromEntries(Object.entries(unlocked).filter(([id]) => ids.has(id)));
  const tabUnlocks = await getTabUnlocks();
  const keptTabs = Object.fromEntries(
    Object.entries(tabUnlocks).filter(([, g]) => ids.has(g.siteId)),
  );
  await chrome.storage.session.set({ unlocked: kept, tabUnlocks: keptTabs });
  await syncRules();
  await sweepTabs();
  return next;
}

// ------------------------------------------------------------- messages ----

async function publicState(senderUrl) {
  const [settings, credential, session] = await Promise.all([
    getSettings(),
    getCredential(),
    getSession(),
  ]);
  const unlocked = await getUnlocked();
  const tabUnlocks = await getTabUnlocks();
  return {
    registered: Boolean(credential),
    rpId: credential?.rpId,
    credentialId: credential?.id,
    settings,
    unlocked,
    tabUnlocks,
    askModes: ASK_MODES,
    adminActive: Boolean(session.admin && session.admin.exp > Date.now()),
    unlockChoices: UNLOCK_CHOICES,
    senderUrl,
  };
}

const handlers = {
  async getState(msg, sender) {
    return publicState(sender.url);
  },

  async challenge(msg) {
    const purpose = msg.purpose;
    if (!['register', 'unlock', 'admin'].includes(purpose)) throw new Error('Bad purpose');
    if (purpose === 'register' && (await getCredential())) await requireAdmin(msg.token);
    const credential = await getCredential();
    return {
      challenge: await issueChallenge(purpose),
      rpId: credential?.rpId,
      credentialId: credential?.id,
    };
  },

  async register(msg) {
    const existing = await getCredential();
    if (existing) await requireAdmin(msg.token);
    const reg = msg.registration;
    const challenge = challengeFromClientData(reg.clientDataJSON);
    await consumeChallenge(challenge, 'register');
    const record = await verifyRegistration(reg, { challenge, origin: ORIGIN });
    record.rpId = typeof msg.rpId === 'string' ? msg.rpId : undefined;
    record.createdAt = Date.now();
    await chrome.storage.local.set({ credential: record });
    if (!existing) {
      const settings = await getSettings();
      await chrome.storage.local.set({ settings: { ...settings, enabled: true } });
    }
    await syncRules();
    await sweepTabs();
    return { token: await grantAdmin() };
  },

  async unlock(msg, sender) {
    await checkAssertion(msg.assertion, 'unlock');
    const url = String(msg.url || '');
    const tabId = sender.tab?.id;

    if (EXTENSIONS_PAGE_RE.test(url)) {
      await chrome.storage.session.set({ extensionsUntil: Date.now() + EXTENSIONS_PAGE_TTL_MS });
      await scheduleRelock(await getUnlocked());
    } else {
      const settings = await getSettings();
      const site = findSite(settings.sites, url);
      if (site && modeFor(site, settings) === 'session') {
        const unlocked = await getUnlocked();
        unlocked[site.id] = settings.unlockMinutes ? Date.now() + settings.unlockMinutes * 60000 : 0;
        await chrome.storage.session.set({ unlocked });
        await syncRules();
        await releaseWaitingTabs(site, tabId);
      } else if (site && tabId !== undefined) {
        // Only this tab, and only for the page load that follows.
        const tabUnlocks = await getTabUnlocks();
        tabUnlocks[tabId] = { siteId: site.id, pendingUntil: Date.now() + TAB_PENDING_TTL_MS };
        await chrome.storage.session.set({ tabUnlocks });
        await syncRules();
      }
    }
    if (tabId !== undefined && /^(https?|chrome|edge|brave|opera|vivaldi):/i.test(url)) {
      await chrome.tabs.update(tabId, { url });
    }
    return {};
  },

  async admin(msg) {
    await checkAssertion(msg.assertion, 'admin');
    return { token: await grantAdmin() };
  },

  async updateSettings(msg) {
    await requireAdmin(msg.token);
    return { settings: await updateSettings(msg.patch || {}) };
  },

  async resetCredential(msg) {
    await requireAdmin(msg.token);
    await chrome.storage.local.remove('credential');
    const settings = await getSettings();
    await chrome.storage.local.set({ settings: { ...settings, enabled: false } });
    await chrome.storage.session.set({ unlocked: {}, tabUnlocks: {}, admin: null, extensionsUntil: 0 });
    await syncRules();
    return {};
  },

  async lockAll() {
    await lockAll();
    return {};
  },

  async lockSite(msg) {
    const unlocked = await getUnlocked();
    delete unlocked[msg.siteId];
    const tabUnlocks = await getTabUnlocks();
    for (const [tabId, g] of Object.entries(tabUnlocks)) {
      if (g.siteId === msg.siteId) delete tabUnlocks[tabId];
    }
    await chrome.storage.session.set({ unlocked, tabUnlocks });
    await syncRules();
    await sweepTabs();
    return {};
  },
};

/** After unlocking a site, other tabs waiting on its lock screen continue too. */
async function releaseWaitingTabs(site, exceptTabId) {
  const tabs = await chrome.tabs.query({});
  await Promise.all(
    tabs
      .filter((t) => t.id !== exceptTabId && t.url?.startsWith(LOCK_URL + '#'))
      .map((t) => {
        const target = t.url.slice(LOCK_URL.length + 1);
        if (findSite([site], target)) return chrome.tabs.update(t.id, { url: target }).catch(() => {});
      }),
  );
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // Only this extension's own pages may talk to the worker.
  if (sender.id !== chrome.runtime.id || !sender.url?.startsWith(ORIGIN + '/')) return false;
  const handler = Object.hasOwn(handlers, msg?.type) && handlers[msg.type];
  if (!handler) return false;
  handler(msg, sender).then(
    (result) => sendResponse({ ok: true, ...result }),
    (err) => sendResponse({ ok: false, error: err.message, code: err.code }),
  );
  return true;
});

// --------------------------------------------------------------- events ----

chrome.webNavigation.onCommitted.addListener(async ({ tabId, frameId, url }) => {
  // Tracks per-tab unlocks across top-level page loads.
  if (frameId !== 0) return;
  const tabUnlocks = await getTabUnlocks();
  const grant = tabUnlocks[tabId];
  if (!grant) return;
  const settings = await getSettings();
  const site = settings.sites.find((s) => s.id === grant.siteId);
  const onSite = site && findSite([site], url);
  if (grant.pendingUntil && onSite) {
    // The unlocked page has loaded: use up the unlock so that a reload or
    // the next visit asks again, while this page keeps working.
    tabUnlocks[tabId] = { siteId: grant.siteId, pendingUntil: 0 };
  } else if (grant.pendingUntil && !url.startsWith(LOCK_URL)) {
    // Still on the way (e.g. a sign-in redirect); keep waiting.
    return;
  } else if (!grant.pendingUntil && !onSite) {
    // The tab left the site (or was locked); coming back asks again.
    delete tabUnlocks[tabId];
  } else {
    return;
  }
  await chrome.storage.session.set({ tabUnlocks });
  await syncRules();
});

chrome.tabs.onActivated.addListener(async () => {
  // "switch" mode: lock any unlocked tab that is no longer in front.
  const [settings, tabUnlocks] = await Promise.all([getSettings(), getTabUnlocks()]);
  let changed = false;
  for (const [tabId, grant] of Object.entries(tabUnlocks)) {
    const site = settings.sites.find((s) => s.id === grant.siteId);
    if (!site || modeFor(site, settings) !== 'switch' || grant.pendingUntil) continue;
    const tab = await chrome.tabs.get(Number(tabId)).catch(() => null);
    if (tab?.active) continue;
    delete tabUnlocks[tabId];
    changed = true;
    if (tab?.url && findSite([site], tab.url)) {
      chrome.tabs.update(tab.id, { url: lockPageFor(tab.url) }).catch(() => {});
    }
  }
  if (changed) {
    await chrome.storage.session.set({ tabUnlocks });
    await syncRules();
  }
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const tabUnlocks = await getTabUnlocks();
  if (!(tabId in tabUnlocks)) return;
  delete tabUnlocks[tabId];
  await chrome.storage.session.set({ tabUnlocks });
  await syncRules();
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo) => {
  // Backstop for navigations DNR does not see: back/forward cache restores,
  // prerendered pages, in-app (history API) navigations after a relock, and
  // the browser's extensions page.
  if (!changeInfo.url) return;
  const target = await lockTargetFor(changeInfo.url, tabId);
  if (target) chrome.tabs.update(tabId, { url: target }).catch(() => {});
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'relock') return;
  await syncRules();
  await sweepTabs();
});

chrome.idle.onStateChanged.addListener(async (state) => {
  if (state !== 'locked') return;
  const settings = await getSettings();
  if (settings.lockOnSystemLock) await lockAll();
});

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  await syncRules();
  if (reason === 'install') chrome.runtime.openOptionsPage();
});

chrome.runtime.onStartup.addListener(() => syncRules());
