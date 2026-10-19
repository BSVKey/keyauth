// Sign in with .key (bsvkey-signin/1): verify that the person signing in controls the
// Bitcoin BSV key that owns a BSVKey name.
//
// Zero dependencies, works in Node 18+ and browsers. Everything is synchronous except the
// optional name-owner lookup. Signatures are the same compact, recoverable Bitcoin Signed
// Message (BSM) envelope BSVKey already uses for inference usage receipts, so any BSV wallet
// library (@bsv/sdk BSM.sign) can produce one.
//
// Flow:
//   1. The service makes a single-use nonce and sends the visitor to
//      https://bsvkey.com/signin#aud=<service origin>&nonce=<nonce>&return=<url on that origin>
//   2. bsvkey.com builds the assertion { v, name, address, aud, nonce, iat, exp }, signs
//      canonical(assertion) with the visitor's key, and returns to
//      <return>#bsvkey_signin=<base64url JSON { assertion, signature }>
//   3. The service calls verifySignin(token, { aud, nonce }) and, for the name check,
//      verifySigninWithOwner(token, { aud, nonce, ownerOf }).
// The key never leaves the visitor's browser; the service only sees a signature.

export const SCHEMA = 'bsvkey-signin/1';
export const NAME_INDEX_URL = 'https://bsvkey.github.io/name-index/names.json';
export const MAX_LIFETIME_MS = 10 * 60 * 1000;
const CLOCK_SKEW_MS = 2 * 60 * 1000;
const NAME_RE = /^[a-z0-9-]{1,64}$/;

// ---------- canonical JSON (sorted keys, no whitespace), same as other BSVKey records ----------
function sortDeep(v) {
  if (Array.isArray(v)) return v.map(sortDeep);
  if (v !== null && typeof v === 'object') { const o = {}; for (const k of Object.keys(v).sort()) if (v[k] !== undefined) o[k] = sortDeep(v[k]); return o; }
  return v;
}
export const canonical = (v) => JSON.stringify(sortDeep(v));

// ---------- bytes ----------
const utf8 = (s) => new TextEncoder().encode(s);
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const concat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let i = 0; for (const x of a) { o.set(x, i); i += x.length; } return o; };
const toBig = (b) => BigInt('0x' + (hex(b) || '0'));
const fromBig = (n, len) => { const s = n.toString(16).padStart(len * 2, '0'); return Uint8Array.from(s.match(/../g), (x) => parseInt(x, 16)); };
function b64decode(s) {
  const t = String(s).replace(/-/g, '+').replace(/_/g, '/');
  if (typeof atob === 'function') return Uint8Array.from(atob(t + '='.repeat((4 - (t.length % 4)) % 4)), (c) => c.charCodeAt(0));
  return new Uint8Array(Buffer.from(t, 'base64'));
}
function b64urlEncode(bytes) {
  let s;
  if (typeof btoa === 'function') s = btoa(String.fromCharCode(...bytes));
  else s = Buffer.from(bytes).toString('base64');
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------- SHA-256 (sync, pure JS) ----------
const K256 = Uint32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]);
export function sha256(msg) {
  const len = msg.length, padLen = ((len + 9 + 63) >> 6) << 6;
  const buf = new Uint8Array(padLen); buf.set(msg); buf[len] = 0x80;
  const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, Math.floor(len / 0x20000000)); dv.setUint32(padLen - 4, (len * 8) >>> 0);
  const H = Uint32Array.from([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = dv.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const t1 = (h + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + ((e & f) ^ (~e & g)) + K256[i] + W[i]) >>> 0;
      const t2 = ((rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) + ((a & b) ^ (a & c) ^ (b & c))) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0; d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
  }
  const out = new Uint8Array(32); const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]);
  return out;
}

// ---------- RIPEMD-160 (same port as the BSVKey Names extension) ----------
export function ripemd160(msg) {
  const zl = [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12,1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13];
  const zr = [5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12,6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13,8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11];
  const sl = [11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8,7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5,11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6];
  const sr = [8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6,9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5,15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11];
  const kl = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  const kr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];
  const f = (j, x, y, z) => j < 16 ? (x ^ y ^ z) : j < 32 ? ((x & y) | (~x & z)) : j < 48 ? ((x | ~y) ^ z) : j < 64 ? ((x & z) | (y & ~z)) : (x ^ (y | ~z));
  const rotl = (x, n) => (x << n) | (x >>> (32 - n));
  const len = msg.length; const padLen = ((len + 8) >> 6) * 64 + 64;
  const buf = new Uint8Array(padLen); buf.set(msg); buf[len] = 0x80;
  const bits = len * 8; const dv = new DataView(buf.buffer);
  dv.setUint32(padLen - 8, bits >>> 0, true); dv.setUint32(padLen - 4, Math.floor(bits / 0x100000000), true);
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  const X = new Array(16);
  for (let off = 0; off < padLen; off += 64) {
    for (let i = 0; i < 16; i++) X[i] = dv.getUint32(off + i * 4, true);
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      let t = (rotl((al + f(j, bl, cl, dl) + X[zl[j]] + kl[j >> 4]) | 0, sl[j]) + el) | 0;
      al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;
      t = (rotl((ar + f(79 - j, br, cr, dr) + X[zr[j]] + kr[j >> 4]) | 0, sr[j]) + er) | 0;
      ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
    }
    const t = (h1 + cl + dr) | 0; h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = t;
  }
  const out = new Uint8Array(20); const odv = new DataView(out.buffer);
  [h0, h1, h2, h3, h4].forEach((h, i) => odv.setUint32(i * 4, h >>> 0, true));
  return out;
}

// ---------- base58check addresses ----------
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function base58(bytes) {
  let n = toBig(bytes), s = '';
  while (n > 0n) { s = B58[Number(n % 58n)] + s; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; s = '1' + s; }
  return s;
}
export function pubkeyToAddress(pub, network = 'main') {
  const payload = concat(Uint8Array.of(network === 'test' ? 0x6f : 0x00), ripemd160(sha256(pub)));
  return base58(concat(payload, sha256(sha256(payload)).subarray(0, 4)));
}

// ---------- secp256k1 public key recovery ----------
const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const G = [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n];
const mod = (a, m = P) => { const r = a % m; return r >= 0n ? r : r + m; };
function inv(a, m = P) {
  let [lo, hi, x0, x1] = [mod(a, m), m, 1n, 0n];
  while (lo > 1n) { const q = hi / lo; [lo, hi] = [hi - q * lo, lo]; [x0, x1] = [x1 - q * x0, x0]; }
  return mod(x0, m);
}
function powmod(b, e, m) { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; }
// Jacobian coordinates [X, Y, Z]; null = point at infinity.
function jdouble(p) {
  if (!p) return null; const [X, Y, Z] = p; if (Y === 0n) return null;
  const S = mod(4n * X * Y * Y), M = mod(3n * X * X), X3 = mod(M * M - 2n * S);
  return [X3, mod(M * (S - X3) - 8n * Y * Y * Y * Y), mod(2n * Y * Z)];
}
function jadd(p, q) {
  if (!p) return q; if (!q) return p;
  const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q;
  const Z1Z1 = mod(Z1 * Z1), Z2Z2 = mod(Z2 * Z2);
  const U1 = mod(X1 * Z2Z2), U2 = mod(X2 * Z1Z1), S1 = mod(Y1 * Z2 * Z2Z2), S2 = mod(Y2 * Z1 * Z1Z1);
  if (U1 === U2) return S1 === S2 ? jdouble(p) : null;
  const H = mod(U2 - U1), R = mod(S2 - S1), H2 = mod(H * H), H3 = mod(H * H2), V = mod(U1 * H2);
  const X3 = mod(R * R - H3 - 2n * V);
  return [X3, mod(R * (V - X3) - S1 * H3), mod(H * Z1 * Z2)];
}
function jmul(p, k) { let r = null; let a = p; while (k > 0n) { if (k & 1n) r = jadd(r, a); a = jdouble(a); k >>= 1n; } return r; }
function affine(p) { if (!p) return null; const zi = inv(p[2]); const zi2 = mod(zi * zi); return [mod(p[0] * zi2), mod(p[1] * zi2 * zi)]; }
const encodePoint = ([x, y], compressed) => compressed ? concat(Uint8Array.of(y & 1n ? 3 : 2), fromBig(x, 32)) : concat(Uint8Array.of(4), fromBig(x, 32), fromBig(y, 32));

function varint(n) { return n < 0xfd ? Uint8Array.of(n) : n <= 0xffff ? Uint8Array.of(0xfd, n & 255, n >> 8) : Uint8Array.of(0xfe, n & 255, (n >> 8) & 255, (n >> 16) & 255, n >>> 24); }
const BSM_PREFIX = utf8('Bitcoin Signed Message:\n');
export function bsmMagicHash(message) {
  const m = typeof message === 'string' ? utf8(message) : message;
  return sha256(sha256(concat(varint(BSM_PREFIX.length), BSM_PREFIX, varint(m.length), m)));
}

// Recover the signer of a 65-byte compact BSM signature (base64). Returns { pubkey (hex), address }
// or throws. Recovery fixes the only public key whose ECDSA check passes for this hash.
export function recoverBsm(message, signatureB64, network = 'main') {
  const sig = b64decode(signatureB64);
  if (sig.length !== 65 || sig[0] < 27 || sig[0] > 34) throw new Error('not a 65-byte compact signature');
  const header = sig[0] - 27, compressed = header >= 4, recid = header & 3;
  const r = toBig(sig.subarray(1, 33)), s = toBig(sig.subarray(33, 65));
  if (r <= 0n || r >= N || s <= 0n || s >= N) throw new Error('signature out of range');
  const x = r + BigInt(recid >> 1) * N;
  if (x >= P) throw new Error('bad recovery id');
  let y = powmod(mod(x * x * x + 7n), (P + 1n) / 4n, P);
  if (mod(y * y) !== mod(x * x * x + 7n)) throw new Error('signature point is not on the curve');
  if ((y & 1n) !== BigInt(recid & 1)) y = P - y;
  const e = mod(toBig(bsmMagicHash(message)), N);
  const ri = inv(r, N);
  const Q = affine(jadd(jmul([x, y, 1n], mod(s * ri, N)), jmul([G[0], G[1], 1n], mod(-e * ri, N))));
  if (!Q) throw new Error('recovered the point at infinity');
  const pub = encodePoint(Q, compressed);
  return { pubkey: hex(pub), address: pubkeyToAddress(pub, network) };
}

// ---------- tokens ----------
export function encodeToken(assertion, signature) { return b64urlEncode(utf8(JSON.stringify({ assertion, signature }))); }
export function decodeToken(token) {
  const o = JSON.parse(new TextDecoder().decode(b64decode(token)));
  if (!o || typeof o !== 'object' || !o.assertion || typeof o.signature !== 'string') throw new Error('token is missing assertion or signature');
  return o;
}
// The exact bytes that are signed.
export const signinMessage = (assertion) => canonical(assertion);

export class SigninError extends Error { constructor(code, message) { super(message); this.code = code; } }
const fail = (code, msg) => { throw new SigninError(code, msg); };

// Check the token itself: shape, audience, nonce, time window, and that the signature recovers
// to the address it claims. Does NOT check name ownership (see verifySigninWithOwner).
export function verifySignin(token, { aud, nonce, now = Date.now(), network = 'main' } = {}) {
  if (!aud) fail('config', 'aud (your origin) is required');
  let t; try { t = typeof token === 'string' ? decodeToken(token) : token; } catch (e) { fail('malformed', `unreadable token: ${e.message}`); }
  const a = t.assertion;
  const allowed = ['v', 'name', 'address', 'aud', 'nonce', 'iat', 'exp'];
  for (const k of Object.keys(a)) if (!allowed.includes(k)) fail('malformed', `unexpected field ${k}`);
  if (a.v !== SCHEMA) fail('malformed', `expected ${SCHEMA}`);
  if (typeof a.name !== 'string' || !NAME_RE.test(a.name)) fail('malformed', 'bad name');
  if (typeof a.address !== 'string') fail('malformed', 'bad address');
  if (a.aud !== aud) fail('audience', `signed for ${a.aud}, not ${aud}`);
  if (nonce !== undefined && a.nonce !== nonce) fail('nonce', 'nonce does not match this sign-in');
  if (typeof a.nonce !== 'string' || a.nonce.length < 16 || a.nonce.length > 128) fail('malformed', 'bad nonce');
  const iat = Date.parse(a.iat), exp = Date.parse(a.exp);
  if (!Number.isFinite(iat) || !Number.isFinite(exp) || exp <= iat) fail('malformed', 'bad iat/exp');
  if (exp - iat > MAX_LIFETIME_MS) fail('expired', 'lifetime longer than allowed');
  if (iat > now + CLOCK_SKEW_MS) fail('expired', 'issued in the future');
  if (now > exp + CLOCK_SKEW_MS) fail('expired', 'sign-in expired, try again');
  let rec; try { rec = recoverBsm(signinMessage(a), t.signature, network); } catch (e) { fail('signature', `bad signature: ${e.message}`); }
  if (rec.address !== a.address) fail('signature', 'signature was not made by the address in the assertion');
  return { name: a.name, address: a.address, pubkey: rec.pubkey, aud: a.aud, nonce: a.nonce, iat: a.iat, exp: a.exp };
}

// Owner lookup from the public BSVKey name index (rebuilt from the chain every few hours).
// Names claimed after the last build are not there yet: those return null.
export function indexOwnerLookup({ url = NAME_INDEX_URL, ttlMs = 60_000, fetchImpl = globalThis.fetch, timeoutMs = 6000 } = {}) {
  let cache = null, at = 0;
  return async function ownerOf(name) {
    if (!cache || Date.now() - at > ttlMs) {
      const ctl = typeof AbortController === 'function' ? new AbortController() : null;
      const timer = ctl ? setTimeout(() => ctl.abort(), timeoutMs) : null;
      try {
        const r = await fetchImpl(url, { signal: ctl?.signal, headers: { accept: 'application/json' } });
        if (!r.ok) throw new Error(`name index HTTP ${r.status}`);
        const j = await r.json();
        if (!j || !j.names) throw new Error('name index has no names');
        cache = j; at = Date.now();
      } finally { if (timer) clearTimeout(timer); }
    }
    const rec = cache.names[String(name).toLowerCase()];
    return rec && rec.owner ? rec.owner : null;
  };
}

// Full check: token valid AND the name is currently owned by the signing address.
export async function verifySigninWithOwner(token, { ownerOf = indexOwnerLookup(), ...opts } = {}) {
  const v = verifySignin(token, opts);
  let owner;
  try { owner = await ownerOf(v.name); } catch (e) { fail('lookup', `could not read the name index: ${e.message}`); }
  if (!owner) fail('owner', `${v.name}.key is not in the name index yet (new claims appear within a few hours)`);
  if (owner !== v.address) fail('owner', `${v.name}.key is owned by a different address`);
  return v;
}

// Helpers for services building the redirect.
export async function newNonce() {
  const b = new Uint8Array(24);
  const c = globalThis.crypto?.getRandomValues ? globalThis.crypto : (await import('node:crypto')).webcrypto;
  c.getRandomValues(b);
  return b64urlEncode(b);
}
export function signinUrl({ aud, nonce, returnTo, base = 'https://bsvkey.com/signin', name } = {}) {
  const p = new URLSearchParams({ aud, nonce, return: returnTo });
  if (name) p.set('name', name);
  return `${base}#${p.toString()}`;
}
