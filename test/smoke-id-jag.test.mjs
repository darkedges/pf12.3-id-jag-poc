import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, sign } from 'node:crypto';
import { verifyIdJag } from '../scripts/smoke-id-jag.mjs';

const now = 1800000000;
const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...publicKey.export({ format: 'jwk' }), kid: 'proof-key', use: 'sig', alg: 'RS256' };
const jwks = { keys: [jwk] };
const expected = {
  issuer: 'https://pf.example.test', audience: 'https://target.example.test',
  clientId: 'target-client', resource: 'https://api.example.test/reports', scope: 'read:reports'
};
function issue(claims = {}, headers = {}) {
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const input = `${encode({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'proof-key', ...headers })}.${encode({
    iss: expected.issuer, aud: expected.audience, client_id: expected.clientId,
    resource: expected.resource, scope: expected.scope, sub: 'user-123', jti: 'unique-fixture',
    iat: now, exp: now + 300, ...claims
  })}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

test('smoke verifier validates a real RSA signature and fixed-profile claims', () => {
  assert.deepEqual(verifyIdJag(issue(), jwks, expected, now), {
    signatureVerified: true, profileClaimsVerified: true, expiresIn: 300
  });
});

test('smoke verifier rejects a tampered signature', () => {
  const parts = issue().split('.');
  const signature = Buffer.from(parts[2], 'base64url');
  signature[0] ^= 1;
  parts[2] = signature.toString('base64url');
  assert.throws(() => verifyIdJag(parts.join('.'), jwks, expected, now), /signature failed/);
});

for (const [name, claims] of Object.entries({
  issuer: { iss: 'https://wrong.example.test' }, audience: { aud: 'https://wrong.example.test' },
  client: { client_id: 'wrong-client' }, resource: { resource: 'https://wrong.example.test/api' },
  scope: { scope: 'admin' }, expiry: { exp: now }, lifetime: { exp: now + 301 },
  future: { iat: now + 60, exp: now + 100 }, replayIdentifier: { jti: '' },
  subject: { sub: '' }, notBefore: { nbf: now + 60 }
})) {
  test(`smoke verifier rejects invalid ${name}`, () => {
    assert.throws(() => verifyIdJag(issue(claims), jwks, expected, now));
  });
}

test('smoke verifier rejects unexpected JWT type and critical headers', () => {
  assert.throws(() => verifyIdJag(issue({}, { typ: 'JWT' }), jwks, expected, now), /JOSE header/);
  assert.throws(() => verifyIdJag(issue({}, { crit: ['custom'] }), jwks, expected, now), /JOSE header/);
});

test('smoke verifier rejects absent and ambiguous signing keys', () => {
  assert.throws(() => verifyIdJag(issue(), { keys: [] }, expected, now), /absent or ambiguous/);
  assert.throws(() => verifyIdJag(issue(), { keys: [jwk, jwk] }, expected, now), /absent or ambiguous/);
});

test('smoke verifier rejects a Base64-wrapped assertion', () => {
  assert.throws(() => verifyIdJag(Buffer.from(issue()).toString('base64url'), jwks, expected, now), /compact JWS/);
});
