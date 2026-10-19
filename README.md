# @bsvkey/keyauth

Sign in with .key: check that a visitor controls the Bitcoin BSV key that owns a BSVKey name. Zero dependencies, Node 18+ and browsers.

## How it works

1. Your site makes a single-use code and sends the visitor to
   `https://bsvkey.com/signin#aud=<your origin>&nonce=<code>&return=<url on your origin>`.
2. bsvkey.com signs `{ v, name, address, aud, nonce, iat, exp }` with the visitor's key, in their browser, as a standard Bitcoin BSV signed message (BSM). It returns to `<return>#bsvkey_signin=<token>`.
3. Your server checks the token:

```js
import { newNonce, signinUrl, verifySigninWithOwner } from '@bsvkey/keyauth';

const nonce = await newNonce();            // store it, single use, ~10 min
res.redirect(signinUrl({ aud: 'https://example.com', nonce, returnTo: 'https://example.com/login' }));

// later, with the token from the URL fragment:
const who = await verifySigninWithOwner(token, { aud: 'https://example.com', nonce });
// -> { name: 'moonbase', address: '1...', pubkey, iat, exp }
```

`verifySigninWithOwner` recovers the signer from the signature, checks site, code and time window (at most 10 minutes), and confirms the address owns the name in the public [name index](https://github.com/BSVKey/name-index), which anyone can rebuild from the chain. Burn the code after one use. Re-check the owner on every login: when a name is sold, the old key stops working.

Errors are `SigninError` with a `code`: `malformed`, `audience`, `nonce`, `expired`, `signature`, `owner`, `lookup`, `config`.

## Other exports

- `verifySignin(token, { aud, nonce })`: token checks only, no name lookup.
- `recoverBsm(message, signatureB64)`: `{ pubkey, address }` of a compact BSM signature.
- `indexOwnerLookup({ url, ttlMs })`: cached name to owner lookup.
- `pubkeyToAddress`, `sha256`, `ripemd160`, `canonical`, `encodeToken`, `decodeToken`.

## Live

- Sign-in page: https://bsvkey.com/signin
- Check a sign-in or any receipt: https://bsvkey.com/verify
- In production on https://paywall.bsvkey.com/credits

MIT licensed.
