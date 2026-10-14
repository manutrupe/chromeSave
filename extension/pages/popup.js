// Toolbar popup. Anything needing a fingerprint/face check opens the settings
// tab instead: on Windows the system dialog takes focus and closes popups.

import { send } from '../lib/client.js';
import { findSite, parsePattern } from '../lib/sites.js';

const $ = (id) => document.getElementById(id);

function openOptions(suffix = '') {
  chrome.tabs.create({ url: chrome.runtime.getURL('pages/options.html') + suffix });
  window.close();
}

(async () => {
  const [state, [tab]] = await Promise.all([
    send('getState'),
    chrome.tabs.query({ active: true, currentWindow: true }),
  ]);
  const { registered, settings, unlocked } = state;
  const on = registered && settings.enabled;

  $('status').textContent = on ? 'On' : 'Off';
  $('status').classList.toggle('on', on);
  $('setup').classList.toggle('hidden', registered);
  $('toggle').classList.toggle('hidden', !registered);
  $('toggle').textContent = settings.enabled ? 'Turn off protection…' : 'Turn on protection…';

  const url = tab?.url || '';
  let host = '';
  try {
    const u = new URL(url);
    if (u.protocol === 'http:' || u.protocol === 'https:') host = u.hostname;
  } catch {}

  const site = host ? findSite(settings.sites, url) : undefined;
  if (!host) {
    $('current').textContent = 'This page cannot be protected.';
  } else if (site) {
    const open =
      site.id in unlocked || state.tabUnlocks[tab.id]?.siteId === site.id;
    $('current').textContent = `${host} is protected${open ? ' (currently unlocked)' : ''}.`;
    $('lock-site').classList.toggle('hidden', !open);
    $('lock-site').addEventListener('click', async () => {
      await send('lockSite', { siteId: site.id });
      window.close();
    });
  } else {
    $('current').textContent = `${host} is not protected.`;
    if (registered && parsePattern(host)) {
      $('protect').classList.remove('hidden');
      $('protect').addEventListener('click', () =>
        openOptions('?add=' + encodeURIComponent(host.replace(/^www\./, ''))),
      );
    }
  }

  $('setup').addEventListener('click', () => openOptions());
  $('settings').addEventListener('click', () => openOptions());
  $('toggle').addEventListener('click', () => openOptions('#disable'));
  $('lock-all').addEventListener('click', async () => {
    await send('lockAll');
    window.close();
  });
})();
