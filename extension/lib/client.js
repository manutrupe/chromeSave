// Page-side helpers: talking to the service worker and running WebAuthn
// ceremonies against the platform authenticator (Windows Hello on Windows,
// Touch ID / iCloud Keychain on macOS).

import { fromB64u, toB64u } from './encoding.js';
import { ALG_ES256, ALG_RS256 } from './webauthn-verify.js';

export async function send(type, data = {}) {
  const res = await chrome.runtime.sendMessage({ type, ...data });
  if (!res) throw new Error('No response from extension');
  if (!res.ok) {
    const err = new Error(res.error);
    err.code = res.code;
    throw err;
  }
  return res;
}

export async function platformAuthenticatorAvailable() {
  try {
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch {
    return false;
  }
}

/** Turns WebAuthn DOMExceptions into messages a person can act on. */
export function describeError(err) {
  if (err?.name === 'NotAllowedError') {
    return 'Verification was cancelled or timed out. Please try again.';
  }
  if (err?.name === 'InvalidStateError') {
    return 'This device is already registered.';
  }
  if (err?.name === 'NotSupportedError') {
    return 'This device has no supported fingerprint, face or PIN authenticator.';
  }
  return err?.message || String(err);
}

// Chrome lets extension pages use their own ID as the WebAuthn relying party.
// Older/other builds instead accept an RP ID covered by host permissions, so
// fall back to "localhost" when the default is refused.
const RP_ID_CANDIDATES = [undefined, 'localhost'];

/**
 * Registers a new platform credential. `token` is required when replacing an
 * existing one. Returns the new admin token.
 */
export async function registerDevice(token) {
  let lastErr;
  for (const rpId of RP_ID_CANDIDATES) {
    const { challenge } = await send('challenge', { purpose: 'register', token });
    let cred;
    try {
      cred = await navigator.credentials.create({
        publicKey: {
          challenge: fromB64u(challenge),
          rp: rpId ? { name: 'ChromeSave', id: rpId } : { name: 'ChromeSave' },
          user: {
            id: crypto.getRandomValues(new Uint8Array(16)),
            name: 'ChromeSave',
            displayName: 'ChromeSave site lock',
          },
          pubKeyCredParams: [
            { type: 'public-key', alg: ALG_ES256 },
            { type: 'public-key', alg: ALG_RS256 },
          ],
          authenticatorSelection: {
            authenticatorAttachment: 'platform',
            userVerification: 'required',
            residentKey: 'discouraged',
          },
          attestation: 'none',
          timeout: 120000,
        },
      });
    } catch (err) {
      lastErr = err;
      if (err?.name === 'SecurityError') continue;
      throw err;
    }
    const r = cred.response;
    const res = await send('register', {
      token,
      rpId,
      registration: {
        id: cred.id,
        clientDataJSON: toB64u(r.clientDataJSON),
        authenticatorData: toB64u(r.getAuthenticatorData()),
        publicKey: r.getPublicKey() ? toB64u(r.getPublicKey()) : null,
        publicKeyAlgorithm: r.getPublicKeyAlgorithm(),
      },
    });
    return res.token;
  }
  throw lastErr;
}

/**
 * Runs a fingerprint / face check and sends the signed assertion to the
 * worker for `purpose` ("unlock" or "admin"). Resolves with the worker's reply.
 */
export async function verifyUser(purpose, extra = {}) {
  const { challenge, rpId, credentialId } = await send('challenge', { purpose });
  if (!credentialId) throw new Error('Set up fingerprint / face unlock in the settings first.');
  const cred = await navigator.credentials.get({
    publicKey: {
      challenge: fromB64u(challenge),
      ...(rpId ? { rpId } : {}),
      allowCredentials: [{ type: 'public-key', id: fromB64u(credentialId), transports: ['internal'] }],
      userVerification: 'required',
      timeout: 120000,
    },
  });
  const r = cred.response;
  return send(purpose, {
    ...extra,
    assertion: {
      id: cred.id,
      clientDataJSON: toB64u(r.clientDataJSON),
      authenticatorData: toB64u(r.authenticatorData),
      signature: toB64u(r.signature),
    },
  });
}
