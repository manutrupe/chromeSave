// Verification of WebAuthn registrations and assertions, run in the service
// worker so that an unlock is only granted for a signature made by the
// platform authenticator (Windows Hello / Touch ID) registered at setup.

import { fromB64u, toB64u } from './encoding.js';

export const ALG_ES256 = -7;
export const ALG_RS256 = -257;

const FLAG_UP = 0x01; // user present
const FLAG_UV = 0x04; // user verified (fingerprint, face, or device PIN)

const utf8 = new TextDecoder();

async function sha256(data) {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', data));
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function checkClientData(clientDataJSON, { type, challenge, origin }) {
  let data;
  try {
    data = JSON.parse(utf8.decode(clientDataJSON));
  } catch {
    throw new Error('Malformed clientDataJSON');
  }
  if (data.type !== type) throw new Error('Unexpected ceremony type');
  if (data.challenge !== challenge) throw new Error('Challenge mismatch');
  if (data.origin !== origin) throw new Error('Origin mismatch');
}

function parseAuthData(authData) {
  if (authData.length < 37) throw new Error('Authenticator data too short');
  return {
    rpIdHash: authData.slice(0, 32),
    flags: authData[32],
    signCount: new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0),
  };
}

function requireUserVerified(flags) {
  if (!(flags & FLAG_UP) || !(flags & FLAG_UV)) {
    throw new Error('Authenticator did not verify the user');
  }
}

// WebAuthn ES256 signatures are ASN.1 DER; WebCrypto expects raw r||s.
export function derToRaw(der) {
  let i = 0;
  if (der[i++] !== 0x30) throw new Error('Bad DER signature');
  if (der[i] & 0x80) i += (der[i] & 0x7f) + 1;
  else i++;
  const readInt = () => {
    if (der[i++] !== 0x02) throw new Error('Bad DER integer');
    const len = der[i++];
    let v = der.slice(i, i + len);
    i += len;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) throw new Error('Bad DER integer length');
    const out = new Uint8Array(32);
    out.set(v, 32 - v.length);
    return out;
  };
  const r = readInt();
  const s = readInt();
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

async function importKey(spki, alg) {
  if (alg === ALG_ES256) {
    return crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, [
      'verify',
    ]);
  }
  if (alg === ALG_RS256) {
    return crypto.subtle.importKey(
      'spki',
      spki,
      { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
      false,
      ['verify'],
    );
  }
  throw new Error(`Unsupported algorithm ${alg}`);
}

/**
 * Validates a registration produced by `navigator.credentials.create` and
 * returns the record to store.
 *
 * @param {{id: string, clientDataJSON: string, authenticatorData: string,
 *          publicKey: string, publicKeyAlgorithm: number}} reg  base64url fields
 * @param {{challenge: string, origin: string}} expected
 */
export async function verifyRegistration(reg, expected) {
  const clientDataJSON = fromB64u(reg.clientDataJSON);
  checkClientData(clientDataJSON, { type: 'webauthn.create', ...expected });
  const authData = fromB64u(reg.authenticatorData);
  const { rpIdHash, flags, signCount } = parseAuthData(authData);
  requireUserVerified(flags);
  if (!reg.publicKey) throw new Error('Authenticator returned no usable public key');
  // Fails early on keys we could never verify later.
  await importKey(fromB64u(reg.publicKey), reg.publicKeyAlgorithm);
  return {
    id: reg.id,
    publicKey: reg.publicKey,
    alg: reg.publicKeyAlgorithm,
    rpIdHash: toB64u(rpIdHash),
    signCount,
  };
}

/**
 * Validates an assertion from `navigator.credentials.get` against the stored
 * credential. Returns the authenticator's new signature counter.
 *
 * @param {{id: string, clientDataJSON: string, authenticatorData: string,
 *          signature: string}} assertion  base64url fields
 * @param {{id: string, publicKey: string, alg: number, rpIdHash: string,
 *          signCount: number}} credential
 * @param {{challenge: string, origin: string}} expected
 */
export async function verifyAssertion(assertion, credential, expected) {
  if (assertion.id !== credential.id) throw new Error('Unknown credential');
  const clientDataJSON = fromB64u(assertion.clientDataJSON);
  checkClientData(clientDataJSON, { type: 'webauthn.get', ...expected });
  const authData = fromB64u(assertion.authenticatorData);
  const { rpIdHash, flags, signCount } = parseAuthData(authData);
  if (!equalBytes(rpIdHash, fromB64u(credential.rpIdHash))) throw new Error('RP ID mismatch');
  requireUserVerified(flags);
  // Platform authenticators may always report 0; only enforce when counting.
  if ((signCount !== 0 || credential.signCount !== 0) && signCount <= credential.signCount) {
    throw new Error('Signature counter did not increase (possible cloned credential)');
  }

  const signed = new Uint8Array(authData.length + 32);
  signed.set(authData, 0);
  signed.set(await sha256(clientDataJSON), authData.length);

  const key = await importKey(fromB64u(credential.publicKey), credential.alg);
  let sig = fromB64u(assertion.signature);
  let algo = { name: 'RSASSA-PKCS1-v1_5' };
  if (credential.alg === ALG_ES256) {
    sig = derToRaw(sig);
    algo = { name: 'ECDSA', hash: 'SHA-256' };
  }
  if (!(await crypto.subtle.verify(algo, key, sig, signed))) {
    throw new Error('Invalid signature');
  }
  return signCount;
}
