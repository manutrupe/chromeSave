import { describeError, send, verifyUser } from '../lib/client.js';

const target = location.hash.slice(1);
const $ = (id) => document.getElementById(id);
const button = $('unlock');

let host = '';
const isExtensionsPage = /^[a-z]+:\/\/extensions\b/i.test(target);
try {
  host = isExtensionsPage ? 'Browser extensions page' : new URL(target).hostname;
} catch {
  host = '';
}

if (isExtensionsPage) {
  $('title').textContent = 'Extension settings are protected';
  document.title = 'Locked – Extensions';
} else if (host) {
  document.title = `Locked – ${host}`;
}
$('site').textContent = host || 'Unknown page';

let busy = false;
let done = false;

async function unlock() {
  if (busy || done) return;
  busy = true;
  button.disabled = true;
  $('error').textContent = '';
  try {
    await verifyUser('unlock', { url: target });
    done = true;
    // The worker navigates this tab to the target once verified.
    button.textContent = 'Unlocked';
  } catch (err) {
    $('error').textContent = describeError(err);
    button.disabled = false;
  } finally {
    busy = false;
  }
}

button.addEventListener('click', unlock);

(async () => {
  const state = await send('getState').catch(() => null);
  if (state && !state.registered) {
    $('error').textContent = 'Fingerprint / face unlock is not set up. Open the settings to set it up.';
    button.disabled = true;
    return;
  }
  // Prompt straight away when this tab is in front, and again whenever you
  // switch back to it; background tabs wait so they don't all pop up the
  // system dialog at once.
  if (document.visibilityState === 'visible' && document.hasFocus()) unlock();
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') unlock();
  });
})();
