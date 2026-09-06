// Local integration fixture only. Never use this issuer or key in production.
import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';

const directory = resolve('.local');
const keyPath = resolve(directory, 'subject-private.pem');
const varsPath = resolve(directory, 'local.tfvars.json');
if (existsSync(keyPath) && existsSync(varsPath)) {
  const inputs = JSON.parse(readFileSync(varsPath, 'utf8'));
  if (!inputs.audience_client_secret) {
    inputs.audience_client_secret = randomBytes(32).toString('base64url');
    writeFileSync(varsPath, JSON.stringify(inputs, null, 2), { mode: 0o600 });
  }
  console.log('Reusing existing local fixture; no keys or existing secrets rotated.');
  process.exit(0);
}
if (existsSync(keyPath) || existsSync(varsPath)) throw new Error('Incomplete fixture exists; refusing to overwrite it');
mkdirSync(directory, { recursive: true });
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const jwk = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'xaa-local-subject', use: 'sig', alg: 'RS256' };
writeFileSync(keyPath, pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), { flag: 'wx', mode: 0o600 });
writeFileSync(varsPath, JSON.stringify({
  local_test_insecure_tls: true,
  subject_issuer: 'https://subject.xaa.example.test',
  subject_jwks: JSON.stringify({ keys: [jwk] }),
  authorized_test_subject: 'xaa-test-user',
  requesting_client_secret: randomBytes(32).toString('base64url'),
  audience_client_secret: randomBytes(32).toString('base64url')
}, null, 2), { flag: 'wx', mode: 0o600 });
console.log('Created local-only fixture key and Terraform inputs under ignored .local/ (no secrets printed).');
