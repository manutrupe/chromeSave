import { test } from 'node:test';
import assert from 'node:assert/strict';
import { findSite, parsePattern, patternToRegex, urlMatches } from '../extension/lib/sites.js';

test('parsePattern normalises common inputs', () => {
  assert.deepEqual(parsePattern('mail.google.com'), { host: 'mail.google.com', path: '' });
  assert.deepEqual(parsePattern(' https://Mail.Google.com/ '), { host: 'mail.google.com', path: '' });
  assert.deepEqual(parsePattern('*.proton.me'), { host: 'proton.me', path: '' });
  assert.deepEqual(parsePattern('icloud.com/mail/'), { host: 'icloud.com', path: '/mail' });
  assert.deepEqual(parsePattern('example.com:8080/a?b=1#c'), { host: 'example.com', path: '/a' });
  assert.deepEqual(parsePattern('localhost'), { host: 'localhost', path: '' });
});

test('parsePattern rejects junk', () => {
  for (const bad of ['', '   ', 'http://', 'exa mple.com', '-bad.com', 'a..b', 'foo.com/ x', null]) {
    assert.equal(parsePattern(bad), null, String(bad));
  }
});

const cases = [
  ['mail.google.com', 'https://mail.google.com/mail/u/0/#inbox', true],
  ['mail.google.com', 'https://MAIL.google.com', true],
  ['mail.google.com', 'http://mail.google.com:443/x', true],
  ['mail.google.com', 'https://google.com/', false],
  ['mail.google.com', 'https://evilmail.google.com.attacker.net/', false],
  ['mail.google.com', 'https://notmail.google.com/', false],
  ['google.com', 'https://mail.google.com/', true],
  ['google.com', 'https://google.com.evil.org/', false],
  ['google.com', 'https://evilgoogle.com/', false],
  ['icloud.com/mail', 'https://www.icloud.com/mail/', true],
  ['icloud.com/mail', 'https://www.icloud.com/mail', true],
  ['icloud.com/mail', 'https://www.icloud.com/mail?x=1', true],
  ['icloud.com/mail', 'https://www.icloud.com/mailbox', false],
  ['icloud.com/mail', 'https://www.icloud.com/photos', false],
  ['mail.google.com', 'chrome://extensions', false],
  ['mail.google.com', 'ftp://mail.google.com/', false],
];

test('urlMatches and the DNR regex agree', () => {
  for (const [pattern, url, expected] of cases) {
    const p = parsePattern(pattern);
    assert.equal(urlMatches(p, url), expected, `urlMatches ${pattern} ${url}`);
    // DNR regex filters are case-insensitive by default.
    const re = new RegExp(patternToRegex(p), 'i');
    // DNR sees the canonical URL, as `new URL` produces it.
    let canonical = url;
    try {
      canonical = new URL(url).href;
    } catch {}
    assert.equal(re.test(canonical), expected, `regex ${pattern} ${canonical}`);
  }
});

test('findSite returns the first matching site', () => {
  const sites = [
    { id: 'a', ...parsePattern('outlook.live.com') },
    { id: 'b', ...parsePattern('mail.google.com') },
  ];
  assert.equal(findSite(sites, 'https://mail.google.com/mail/')?.id, 'b');
  assert.equal(findSite(sites, 'https://example.com/'), undefined);
});
