import {
  describeError,
  platformAuthenticatorAvailable,
  registerDevice,
  send,
  verifyUser,
} from '../lib/client.js';
import { formatPattern, parsePattern, PRESETS } from '../lib/sites.js';

const $ = (id) => document.getElementById(id);

// Admin token from the worker; only kept in memory, so a reload asks again.
let token = null;
let state = null;

function showError(err) {
  $('error').textContent = err ? describeError(err) : '';
}

async function refresh() {
  state = await send('getState');
  render();
}

const MODE_LABELS = {
  session: 'Once per session',
  open: 'Every page open',
  switch: 'Every tab switch',
};

const MODE_HINTS = {
  session:
    'One check unlocks the site in all tabs until the time below runs out, Chrome closes, or the computer locks.',
  open:
    'Each tab asks separately. Reloading, opening the site in a new tab, or coming back to it after leaving asks again.',
  switch:
    'Like "every time the page is opened", and the tab also locks as soon as you switch to another tab. Coming back asks again (the page reloads after unlocking).',
};

function isSiteUnlocked(site) {
  return (
    site.id in state.unlocked ||
    Object.values(state.tabUnlocks).some((g) => g.siteId === site.id)
  );
}

function minutesLabel(m) {
  if (m === 0) return 'until Chrome is closed';
  if (m < 60) return `${m} minute${m === 1 ? '' : 's'}`;
  return `${m / 60} hour${m === 60 ? '' : 's'}`;
}

function render() {
  const { registered, settings } = state;
  const unlocked = token !== null;
  $('setup').classList.toggle('hidden', registered);
  $('locked').classList.toggle('hidden', !registered || unlocked);
  $('manage').classList.toggle('hidden', !registered || !unlocked);

  const n = settings.sites.length;
  const summary = settings.enabled
    ? `Protection is ON for ${n} site${n === 1 ? '' : 's'}.`
    : 'Protection is OFF. Protected sites open without a fingerprint or face check.';
  $('locked-status').textContent = summary;
  $('protection-text').textContent = summary;
  $('enabled').checked = settings.enabled;

  const list = $('sites');
  list.replaceChildren();
  if (!n) {
    const li = document.createElement('li');
    li.className = 'empty';
    li.textContent = 'No sites yet. Add one above or pick a preset.';
    list.append(li);
  }
  for (const site of settings.sites) {
    const li = document.createElement('li');
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = formatPattern(site);
    if (site.label) {
      const small = document.createElement('small');
      small.textContent = site.label;
      name.append(small);
    }
    const right = document.createElement('span');
    right.className = 'row';
    const mode = document.createElement('select');
    mode.title = 'When to ask for this site';
    const defaultLabel = MODE_LABELS[settings.askMode].toLowerCase();
    mode.add(new Option(`Default (${defaultLabel})`, 'default'));
    for (const m of state.askModes) mode.add(new Option(MODE_LABELS[m], m));
    mode.value = state.askModes.includes(site.askMode) ? site.askMode : 'default';
    mode.addEventListener('change', () =>
      saveSites(settings.sites.map((s) => (s.id === site.id ? { ...s, askMode: mode.value } : s))),
    );
    right.append(mode);
    if (isSiteUnlocked(site)) {
      const lockBtn = document.createElement('button');
      lockBtn.textContent = 'Lock now';
      lockBtn.addEventListener('click', () => act(() => send('lockSite', { siteId: site.id })));
      right.append(lockBtn);
    }
    const remove = document.createElement('button');
    remove.className = 'danger';
    remove.textContent = 'Remove';
    remove.addEventListener('click', () =>
      saveSites(settings.sites.filter((s) => s.id !== site.id)),
    );
    right.append(remove);
    li.append(name, right);
    list.append(li);
  }

  const presets = $('presets');
  presets.replaceChildren();
  const existing = new Set(settings.sites.map(formatPattern));
  for (const p of PRESETS) {
    if (existing.has(formatPattern(parsePattern(p.pattern)))) continue;
    const b = document.createElement('button');
    b.type = 'button';
    b.textContent = `+ ${p.label}`;
    b.addEventListener('click', () => saveSites([...settings.sites, p]));
    presets.append(b);
  }

  const select = $('unlock-minutes');
  if (!select.options.length) {
    for (const m of state.unlockChoices) select.add(new Option(minutesLabel(m), String(m)));
  }
  select.value = String(settings.unlockMinutes);
  $('ask-mode').value = settings.askMode;
  $('ask-mode-hint').textContent = MODE_HINTS[settings.askMode];
  // The duration only applies to sites that ask once per session.
  const usesDuration =
    settings.askMode === 'session' || settings.sites.some((s) => s.askMode === 'session');
  $('unlock-minutes-field').classList.toggle('hidden', !usesDuration);
  $('lock-on-system-lock').checked = settings.lockOnSystemLock;
  $('guard-extensions').checked = settings.guardExtensionsPage;

  $('device-text').textContent = registered
    ? 'A fingerprint / face credential from this computer is registered. Register again if you reset Windows Hello or Touch ID.'
    : '';
}

/** Runs an action, handling an expired admin session by locking the page. */
async function act(fn) {
  showError(null);
  try {
    await fn();
  } catch (err) {
    if (err.code === 'auth_required') token = null;
    showError(err);
  }
  await refresh();
}

function update(patch) {
  return act(() => send('updateSettings', { token, patch }));
}

function saveSites(sites) {
  return update({
    sites: sites.map((s) => ({
      pattern: s.pattern ?? formatPattern(s),
      label: s.label || '',
      askMode: s.askMode || 'default',
    })),
  });
}

// ------------------------------------------------------------- wiring ------

$('register').addEventListener('click', () =>
  act(async () => {
    $('register').disabled = true;
    try {
      token = await registerDevice();
    } finally {
      $('register').disabled = false;
    }
  }),
);

$('verify').addEventListener('click', () =>
  act(async () => {
    ({ token } = await verifyUser('admin'));
  }),
);

$('enabled').addEventListener('change', (e) => update({ enabled: e.target.checked }));
$('ask-mode').addEventListener('change', (e) => update({ askMode: e.target.value }));
$('unlock-minutes').addEventListener('change', (e) =>
  update({ unlockMinutes: Number(e.target.value) }),
);
$('lock-on-system-lock').addEventListener('change', (e) =>
  update({ lockOnSystemLock: e.target.checked }),
);
$('guard-extensions').addEventListener('change', (e) =>
  update({ guardExtensionsPage: e.target.checked }),
);

$('add-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('add-input');
  const parsed = parsePattern(input.value);
  if (!parsed) {
    showError(new Error(`"${input.value}" doesn't look like a website address.`));
    return;
  }
  input.value = '';
  saveSites([...state.settings.sites, { pattern: formatPattern(parsed) }]);
});

for (const id of ['lock-all', 'lock-all-locked']) {
  $(id).addEventListener('click', () =>
    act(async () => {
      await send('lockAll');
      token = null;
    }),
  );
}

$('reregister').addEventListener('click', () =>
  act(async () => {
    token = await registerDevice(token);
  }),
);

$('reset').addEventListener('click', () => {
  if (!confirm('Remove the registered fingerprint / face and turn protection off?')) return;
  act(async () => {
    await send('resetCredential', { token });
    token = null;
  });
});

// ------------------------------------------------------------- startup -----

(async () => {
  await refresh();
  if (!state.registered && !(await platformAuthenticatorAvailable())) {
    $('no-platform').classList.remove('hidden');
  }
  // Pre-fill from the popup's "Protect this site" button.
  const add = new URLSearchParams(location.search).get('add');
  if (add) $('add-input').value = add;
  // The popup's "Turn off" button lands here; ask for verification right away.
  if (state.registered && (location.hash === '#disable' || add) && document.hasFocus()) {
    $('verify').click();
  }
})();
