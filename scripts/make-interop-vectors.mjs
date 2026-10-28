#!/usr/bin/env node
// Prints the interoperability vectors of SignatureTests, KeyAgreementTests and
// MessageAuthenticatorTests, computed with Node's own crypto (OpenSSL), not with CryptoKit.
// Usage: node scripts/make-interop-vectors.mjs
import crypto from 'node:crypto';

const hex = (buffer) => Buffer.from(buffer).toString('hex');
const message = Buffer.from('Signed by another implementation');

// Ed25519 key from a fixed 32-byte seed (PKCS #8 prefix of RFC 8410 + seed).
const seed = Buffer.from('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60', 'hex');
const edPrivate = crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
});
const edPublic = crypto.createPublicKey(edPrivate);
console.log('ed25519.publicPEM', JSON.stringify(edPublic.export({ format: 'pem', type: 'spki' })));
console.log('ed25519.signature', hex(crypto.sign(null, message, edPrivate)));

// P-256 key from a fixed scalar.
const scalar = Buffer.from('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721', 'hex');
const ecdh = crypto.createECDH('prime256v1');
ecdh.setPrivateKey(scalar);
const point = ecdh.getPublicKey();
const jwk = {
  kty: 'EC', crv: 'P-256',
  d: scalar.toString('base64url'),
  x: point.subarray(1, 33).toString('base64url'),
  y: point.subarray(33).toString('base64url'),
};
const p256Private = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
const p256Public = crypto.createPublicKey(p256Private);
console.log('p256.publicDER', hex(p256Public.export({ format: 'der', type: 'spki' })));
console.log('p256.signatureRaw', hex(crypto.sign('sha256', message, { key: p256Private, dsaEncoding: 'ieee-p1363' })));
console.log('p256.signatureDER', hex(crypto.sign('sha256', message, { key: p256Private, dsaEncoding: 'der' })));

// X25519 (RFC 7748 §6.1 keys) followed by HKDF-SHA256.
const x25519 = (raw) => crypto.createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), Buffer.from(raw, 'hex')]),
  format: 'der',
  type: 'pkcs8',
});
const alice = x25519('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a');
const bob = x25519('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb');
const rawPublic = (key) => crypto.createPublicKey(key).export({ format: 'der', type: 'spki' }).subarray(12);
console.log('x25519.bobPublic', hex(rawPublic(bob)));
const secret = crypto.diffieHellman({ privateKey: alice, publicKey: crypto.createPublicKey(bob) });
console.log('x25519.secret', hex(secret));
console.log('x25519.hkdf', hex(crypto.hkdfSync('sha256', secret, Buffer.from('salt-1'), Buffer.from('sync v1'), 32)));

// HMAC, RFC 4231 test case 4.
const hmacKey = Buffer.from('0102030405060708090a0b0c0d0e0f10111213141516171819', 'hex');
const hmacData = Buffer.alloc(50, 0xcd);
for (const algorithm of ['sha256', 'sha384', 'sha512']) {
  console.log(`hmac.${algorithm}`, crypto.createHmac(algorithm, hmacKey).update(hmacData).digest('hex'));
}

// JSON Web Tokens over the same claims, signed with the keys above and an HS256 key.
const b64url = (buffer) => Buffer.from(buffer).toString('base64url');
const claims = { iss: 'https://auth.example.com', sub: 'user-42', aud: ['ios-app', 'web'], iat: 1767225600, nbf: 1767225600, exp: 4102444800, scope: 'read' };
const jwt = (alg, sign) => {
  const input = `${b64url(JSON.stringify({ alg, typ: 'JWT' }))}.${b64url(JSON.stringify(claims))}`;
  return `${input}.${b64url(sign(Buffer.from(input)))}`;
};
const hsKey = Buffer.from('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f', 'hex');
console.log('jwt.hs256', jwt('HS256', (input) => crypto.createHmac('sha256', hsKey).update(input).digest()));
console.log('jwt.es256', jwt('ES256', (input) => crypto.sign('sha256', input, { key: p256Private, dsaEncoding: 'ieee-p1363' })));
console.log('jwt.eddsa', jwt('EdDSA', (input) => crypto.sign(null, input, edPrivate)));
