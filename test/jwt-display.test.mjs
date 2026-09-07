import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeCompactJwt, printDecodedJwt, showJwtRequested } from '../src/jwt-display.mjs';

const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
const token = `${encode({ alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'test-key' })}.${encode({ sub: 'user-123', scope: 'read:reports' })}.signature`;

test('decodes JWT header and body without exposing the signature', () => {
  const decoded = decodeCompactJwt(token);
  assert.deepEqual(decoded.header, { alg: 'RS256', typ: 'oauth-id-jag+jwt', kid: 'test-key' });
  assert.deepEqual(decoded.payload, { sub: 'user-123', scope: 'read:reports' });
  assert.equal(decoded.signaturePresent, true);
});

test('rejects wrapped or malformed JWT values', () => {
  assert.throws(() => decodeCompactJwt(Buffer.from(token).toString('base64url')), /compact JWT/);
  assert.throws(() => decodeCompactJwt('one.two'), /compact JWT/);
  assert.throws(() => decodeCompactJwt('one.two.three!'), /compact JWT/);
});

test('displays by default and supports explicit opt-out flags', () => {
  assert.equal(showJwtRequested(['node', 'script', '--show-jwt'], {}), true);
  assert.equal(showJwtRequested(['node', 'script'], { XAA_SHOW_JWT: 'true' }), true);
  assert.equal(showJwtRequested(['node', 'script'], { XAA_SHOW_JWT: 'false' }), false);
  assert.equal(showJwtRequested(['node', 'script'], {}), true);
  assert.equal(showJwtRequested(['node', 'script', '--no-show-jwt'], {}), false);
});

test('colors JSON attribute names and values independently', () => {
  let output = '';
  const stream = { isTTY: true, write: value => { output += value; } };
  const previousColor = process.env.XAA_COLOR;
  process.env.XAA_COLOR = 'always';
  try {
    printDecodedJwt(token, { stream, label: 'Color test' });
  } finally {
    if (previousColor === undefined) delete process.env.XAA_COLOR;
    else process.env.XAA_COLOR = previousColor;
  }
  assert.match(output, /\u001b\[36m"alg"\u001b\[0m/);
  assert.match(output, /\u001b\[32m"oauth-id-jag\+jwt"\u001b\[0m/);
});
