// Parsing and matching of the user's protected-site patterns.
//
// A pattern is a host, optionally followed by a path prefix:
//   "mail.google.com"         -> that host and any of its subdomains
//   "outlook.live.com/mail"   -> only URLs whose path starts with /mail
//   "https://*.proton.me/"    -> scheme, "*." and trailing "/" are ignored
//
// The same pattern is turned into a JS matcher (for sweeping open tabs) and an
// RE2-compatible regex (for declarativeNetRequest rules), so both must agree.

const HOST_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]+(\.[a-z0-9-]+)*$/;

/**
 * Normalises user input into { host, path } or returns null when invalid.
 * @param {string} input
 */
export function parsePattern(input) {
  if (typeof input !== 'string') return null;
  let s = input.trim().toLowerCase();
  if (!s) return null;
  s = s.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  s = s.replace(/^\*\./, '');
  s = s.replace(/[?#].*$/, '');
  const slash = s.indexOf('/');
  let host = slash === -1 ? s : s.slice(0, slash);
  let path = slash === -1 ? '' : s.slice(slash);
  host = host.replace(/:\d+$/, '').replace(/\.$/, '');
  path = path.replace(/\/+$/, '');
  if (!HOST_RE.test(host)) return null;
  if (path && !/^\/[\x21-\x7e]*$/.test(path)) return null;
  return { host, path };
}

/** Canonical string form of a pattern, used for display and de-duplication. */
export function formatPattern({ host, path }) {
  return host + path;
}

function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');
}

/**
 * RE2-compatible regex matching http(s) URLs covered by the pattern.
 * @param {{host: string, path: string}} p
 */
export function patternToRegex({ host, path }) {
  return (
    '^https?://([^/?#]*\\.)?' +
    escapeRegex(host) +
    '(:[0-9]+)?' +
    escapeRegex(path) +
    '([/?#].*)?$'
  );
}

/**
 * True if `url` falls under the pattern.
 * @param {{host: string, path: string}} p
 * @param {string} url
 */
export function urlMatches({ host, path }, url) {
  let u;
  try {
    u = new URL(url);
  } catch {
    return false;
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
  const h = u.hostname.toLowerCase().replace(/\.$/, '');
  if (h !== host && !h.endsWith('.' + host)) return false;
  if (!path) return true;
  const p = u.pathname.toLowerCase();
  return p === path || p.startsWith(path + '/');
}

/**
 * Returns the first site whose pattern covers `url`, or undefined.
 * @param {Array<{id: string, host: string, path: string}>} sites
 * @param {string} url
 */
export function findSite(sites, url) {
  return sites.find((s) => urlMatches(s, url));
}

/** Common webmail sites offered as one-click presets. */
export const PRESETS = [
  { label: 'Gmail', pattern: 'mail.google.com' },
  { label: 'Outlook', pattern: 'outlook.live.com' },
  { label: 'Outlook (Office 365)', pattern: 'outlook.office.com' },
  { label: 'Yahoo Mail', pattern: 'mail.yahoo.com' },
  { label: 'Proton Mail', pattern: 'mail.proton.me' },
  { label: 'iCloud Mail', pattern: 'icloud.com/mail' },
];
