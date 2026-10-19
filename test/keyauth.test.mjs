// Cross-checks the zero-dep verifier against @bsv/sdk (the same library bsvkey.com signs with).
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import * as KA from '../src/keyauth.mjs';

// The SDK bundle bsvkey.com serves (vendor.js). BSVKEY_VENDOR overrides the path.
const require = createRequire(import.meta.url);
globalThis.window = globalThis; globalThis.self = globalThis;
if (!globalThis.crypto) globalThis.crypto = crypto.webcrypto;   // Node 18: the SDK's key generator needs a global crypto
require(process.env.BSVKEY_VENDOR || '../vendor.js');
const { PrivateKey, BSM, Utils } = globalThis.bsvsdk;

const AUD = 'https://paywall.bsvkey.com';
function makeToken(priv, over = {}, now = Date.now()) {
  const assertion = {
    v: KA.SCHEMA, name: 'moonbase', address: priv.toAddress().toString(), aud: AUD,
    nonce: 'n'.repeat(20), iat: new Date(now).toISOString(), exp: new Date(now + 5 * 60_000).toISOString(), ...over,
  };
  const signature = BSM.sign(Utils.toArray(KA.signinMessage(assertion), 'utf8'), priv, 'base64');
  return { token: KA.encodeToken(assertion, signature), assertion, signature };
}

test('sha256 and ripemd160 match node:crypto', () => {
  for (const n of [0, 1, 55, 56, 63, 64, 65, 119, 120, 1000]) {
    const b = crypto.randomBytes(n);
    assert.equal(Buffer.from(KA.sha256(b)).toString('hex'), crypto.createHash('sha256').update(b).digest('hex'));
    let rmd = null; try { rmd = crypto.createHash('ripemd160').update(b).digest('hex'); } catch {}
    if (rmd) assert.equal(Buffer.from(KA.ripemd160(b)).toString('hex'), rmd);
  }
});

test('recovers the signer of @bsv/sdk BSM signatures (40 random keys)', () => {
  for (let i = 0; i < 40; i++) {
    const p = PrivateKey.fromRandom();
    const msg = `hello ${i} ${'x'.repeat(i * 7)}`;
    const sig = BSM.sign(Utils.toArray(msg, 'utf8'), p, 'base64');
    const r = KA.recoverBsm(msg, sig);
    assert.equal(r.address, p.toAddress().toString());
    assert.equal(r.pubkey, p.toPublicKey().toString());
  }
});

test('long message (varint 0xfd length prefix)', () => {
  const p = PrivateKey.fromRandom(); const msg = 'y'.repeat(300);
  const sig = BSM.sign(Utils.toArray(msg, 'utf8'), p, 'base64');
  assert.equal(KA.recoverBsm(msg, sig).address, p.toAddress().toString());
});

test('testnet address encoding', () => {
  const p = PrivateKey.fromRandom(); const sig = BSM.sign(Utils.toArray('t', 'utf8'), p, 'base64');
  assert.equal(KA.recoverBsm('t', sig, 'test').address, p.toAddress('testnet').toString());
});

test('valid sign-in passes', () => {
  const p = PrivateKey.fromRandom(); const { token, assertion } = makeToken(p);
  const v = KA.verifySignin(token, { aud: AUD, nonce: assertion.nonce });
  assert.equal(v.name, 'moonbase'); assert.equal(v.address, assertion.address);
});

test('rejects wrong audience, nonce, expiry, future iat, long lifetime', () => {
  const p = PrivateKey.fromRandom();
  const code = (fn) => { try { fn(); return 'none'; } catch (e) { return e.code; } };
  const { token, assertion } = makeToken(p);
  assert.equal(code(() => KA.verifySignin(token, { aud: 'https://evil.example', nonce: assertion.nonce })), 'audience');
  assert.equal(code(() => KA.verifySignin(token, { aud: AUD, nonce: 'm'.repeat(20) })), 'nonce');
  assert.equal(code(() => KA.verifySignin(token, { aud: AUD, now: Date.now() + 60 * 60_000 })), 'expired');
  assert.equal(code(() => KA.verifySignin(makeToken(p, {}, Date.now() + 60 * 60_000).token, { aud: AUD })), 'expired');
  const now = Date.now();
  assert.equal(code(() => KA.verifySignin(makeToken(p, { exp: new Date(now + 60 * 60_000).toISOString() }, now).token, { aud: AUD })), 'expired');
  assert.equal(code(() => KA.verifySignin(token, {})), 'config');
});

test('rejects tampered name, address swap, extra fields, junk', () => {
  const p = PrivateKey.fromRandom(), q = PrivateKey.fromRandom();
  const code = (fn) => { try { fn(); return 'none'; } catch (e) { return e.code; } };
  const { assertion, signature } = makeToken(p);
  assert.equal(code(() => KA.verifySignin(KA.encodeToken({ ...assertion, name: 'satoshi' }, signature), { aud: AUD })), 'signature');
  assert.equal(code(() => KA.verifySignin(KA.encodeToken({ ...assertion, address: q.toAddress().toString() }, signature), { aud: AUD })), 'signature');
  assert.equal(code(() => KA.verifySignin(KA.encodeToken({ ...assertion, admin: true }, signature), { aud: AUD })), 'malformed');
  assert.equal(code(() => KA.verifySignin('not-a-token', { aud: AUD })), 'malformed');
  assert.equal(code(() => KA.verifySignin(KA.encodeToken(assertion, 'AAAA'), { aud: AUD })), 'signature');
  // Signed by q but claims p's address.
  const forged = { ...assertion }; const sigQ = BSM.sign(Utils.toArray(KA.signinMessage(forged), 'utf8'), q, 'base64');
  assert.equal(code(() => KA.verifySignin(KA.encodeToken(forged, sigQ), { aud: AUD })), 'signature');
});

test('owner check via name index', async () => {
  const p = PrivateKey.fromRandom(); const { token, assertion } = makeToken(p);
  const idx = (owner) => KA.indexOwnerLookup({ fetchImpl: async () => ({ ok: true, json: async () => ({ names: owner ? { moonbase: { owner } } : {} }) }) });
  const ok = await KA.verifySigninWithOwner(token, { aud: AUD, nonce: assertion.nonce, ownerOf: idx(assertion.address) });
  assert.equal(ok.name, 'moonbase');
  await assert.rejects(KA.verifySigninWithOwner(token, { aud: AUD, ownerOf: idx('1BoatSLRHtKNngkdXEeobR76b53LETtpyT') }), { code: 'owner' });
  await assert.rejects(KA.verifySigninWithOwner(token, { aud: AUD, ownerOf: idx(null) }), { code: 'owner' });
  await assert.rejects(KA.verifySigninWithOwner(token, { aud: AUD, ownerOf: async () => { throw new Error('down'); } }), { code: 'lookup' });
});

test('signinUrl puts everything in the fragment', async () => {
  const n = await KA.newNonce();
  assert.ok(n.length >= 30);
  const u = KA.signinUrl({ aud: AUD, nonce: n, returnTo: AUD + '/credits' });
  assert.ok(u.startsWith('https://bsvkey.com/signin#'));
  assert.equal(new URLSearchParams(u.split('#')[1]).get('return'), AUD + '/credits');
});
