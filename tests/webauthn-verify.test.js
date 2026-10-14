import { test } from 'node:test';
import assert from 'node:assert/strict';
import { toB64u } from '../extension/lib/encoding.js';
import {
  ALG_ES256,
  ALG_RS256,
  derToRaw,
  verifyAssertion,
  verifyRegistration,
} from '../extension/lib/webauthn-verify.js';

const ORIGIN = 'chrome-extension://abcdefghijklmnopabcdefghijklmnop';
const enc = new TextEncoder();

function rawToDer(raw) {
  const int = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let v = bytes.slice(i);
    if (v[0] & 0x80) v = Uint8Array.of(0, ...v);
    return [0x02, v.length, ...v];
  };
  const body = [...int(raw.slice(0, 32)), ...int(raw.slice(32))];
  return Uint8Array.from([0x30, body.length, ...body]);
}

async function makeAuthenticator(alg) {
  const params =
    alg === ALG_ES256
      ? { name: 'ECDSA', namedCurve: 'P-256' }
      : { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1), hash: 'SHA-256' };
  const keys = await crypto.subtle.generateKey(params, true, ['sign', 'verify']);
  const spki = new Uint8Array(await crypto.subtle.exportKey('spki', keys.publicKey));
  const rpIdHash = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode('rp')));
  let counter = 0;

  const authData = (flags, count) => {
    const a = new Uint8Array(37);
    a.set(rpIdHash);
    a[32] = flags;
    new DataView(a.buffer).setUint32(33, count);
    return a;
  };

  return {
    id: 'cred-1',
    register(challenge, { flags = 0x05, type = 'webauthn.create', origin = ORIGIN } = {}) {
      return {
        id: 'cred-1',
        clientDataJSON: toB64u(enc.encode(JSON.stringify({ type, challenge, origin }))),
        authenticatorData: toB64u(authData(flags, 0)),
        publicKey: toB64u(spki),
        publicKeyAlgorithm: alg,
      };
    },
    async assert(challenge, { flags = 0x05, origin = ORIGIN, count = ++counter, tamper = false } = {}) {
      const clientData = enc.encode(JSON.stringify({ type: 'webauthn.get', challenge, origin }));
      const ad = authData(flags, count);
      const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientData));
      const signed = new Uint8Array([...ad, ...hash]);
      let sig = new Uint8Array(
        await crypto.subtle.sign(
          alg === ALG_ES256 ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSASSA-PKCS1-v1_5' },
          keys.privateKey,
          signed,
        ),
      );
      if (alg === ALG_ES256) sig = rawToDer(sig);
      if (tamper) ad[36] ^= 0xff;
      return {
        id: 'cred-1',
        clientDataJSON: toB64u(clientData),
        authenticatorData: toB64u(ad),
        signature: toB64u(sig),
      };
    },
  };
}

for (const [name, alg] of [
  ['ES256 (Touch ID)', ALG_ES256],
  ['RS256 (Windows Hello)', ALG_RS256],
]) {
  test(`${name}: register then verify assertions`, async () => {
    const auth = await makeAuthenticator(alg);
    const cred = await verifyRegistration(auth.register('c0'), { challenge: 'c0', origin: ORIGIN });
    assert.equal(cred.alg, alg);

    const count = await verifyAssertion(await auth.assert('c1'), cred, { challenge: 'c1', origin: ORIGIN });
    assert.equal(count, 1);
    cred.signCount = count;

    await assert.rejects(
      verifyAssertion(await auth.assert('c2'), cred, { challenge: 'other', origin: ORIGIN }),
      /Challenge mismatch/,
    );
    await assert.rejects(
      verifyAssertion(await auth.assert('c3', { origin: 'https://evil.example' }), cred, {
        challenge: 'c3',
        origin: ORIGIN,
      }),
      /Origin mismatch/,
    );
    await assert.rejects(
      verifyAssertion(await auth.assert('c4', { flags: 0x01 }), cred, { challenge: 'c4', origin: ORIGIN }),
      /did not verify the user/,
    );
    await assert.rejects(
      verifyAssertion(await auth.assert('c5', { tamper: true }), cred, { challenge: 'c5', origin: ORIGIN }),
      /Invalid signature|counter/,
    );
    await assert.rejects(
      verifyAssertion(await auth.assert('c6', { count: 1 }), cred, { challenge: 'c6', origin: ORIGIN }),
      /counter/,
    );
  });
}

test('registration requires user verification and the right ceremony', async () => {
  const auth = await makeAuthenticator(ALG_ES256);
  await assert.rejects(
    verifyRegistration(auth.register('c', { flags: 0x01 }), { challenge: 'c', origin: ORIGIN }),
    /did not verify the user/,
  );
  await assert.rejects(
    verifyRegistration(auth.register('c', { type: 'webauthn.get' }), { challenge: 'c', origin: ORIGIN }),
    /ceremony type/,
  );
});

test('authenticators that always report counter 0 are accepted', async () => {
  const auth = await makeAuthenticator(ALG_ES256);
  const cred = await verifyRegistration(auth.register('c0'), { challenge: 'c0', origin: ORIGIN });
  for (const c of ['a', 'b']) {
    await verifyAssertion(await auth.assert(c, { count: 0 }), cred, { challenge: c, origin: ORIGIN });
  }
});

test('derToRaw handles leading-zero integers', () => {
  const raw = new Uint8Array(64);
  raw[0] = 0x80; // forces a 0x00 pad byte in DER
  raw[63] = 1; // s with many leading zeros
  assert.deepEqual(derToRaw(rawToDer(raw)), raw);
});
