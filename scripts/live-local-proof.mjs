// Local fixture test, not a real OIDC login or a downstream redemption test.
// The TLS exception below applies only to localhost and never changes global TLS.
import https from 'node:https';
import { readFileSync } from 'node:fs';
import { randomUUID, sign } from 'node:crypto';
import { verifyIdJag } from './smoke-id-jag.mjs';

const config = JSON.parse(readFileSync('.local/local.tfvars.json', 'utf8'));
const privateKey = readFileSync('.local/subject-private.pem', 'utf8');
const clientId = config.requesting_client_id || 'xaa-primary-client';
const expected = {
  issuer: config.pf_issuer || 'https://localhost:9031',
  audience: config.target_issuer || 'https://target.example.test',
  clientId: config.target_client_id || 'target-client',
  resource: config.target_resource || 'https://api.example.test/reports',
  scope: (config.allowed_scopes || ['read:reports']).sort().join(' ')
};
if (expected.issuer !== 'https://localhost:9031') throw new Error('This fixture runner targets only https://localhost:9031');

function subject(overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const encode = x => Buffer.from(JSON.stringify(x)).toString('base64url');
  const input = `${encode({ alg: 'RS256', typ: 'JWT', kid: 'xaa-local-subject' })}.${encode({
    iss: config.subject_issuer, sub: config.authorized_test_subject, aud: clientId,
    azp: clientId, iat: now, exp: now + 300, jti: randomUUID(), ...overrides
  })}`;
  return `${input}.${sign('RSA-SHA256', Buffer.from(input), privateKey).toString('base64url')}`;
}

function call(path, params, credentials = [clientId, config.requesting_client_secret]) {
  const body = params?.toString();
  return new Promise((resolve, reject) => {
    const headers = body ? { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } : {};
    if (body && credentials) {
      const encode = value => new URLSearchParams({ v: value }).toString().slice(2);
      headers.Authorization = 'Basic ' + Buffer.from(credentials.map(encode).join(':')).toString('base64');
    }
    const req = https.request({ hostname: 'localhost', port: 9031, path,
      method: body ? 'POST' : 'GET', headers, rejectUnauthorized: !config.local_test_insecure_tls,
      timeout: 10000
    }, res => {
      let bytes = 0; const chunks = [];
      res.on('data', chunk => { bytes += chunk.length; if (bytes > 131072) req.destroy(new Error('Response too large')); else chunks.push(chunk); });
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(Buffer.concat(chunks).toString()) }); }
        catch { reject(new Error('Expected a JSON response')); }
      });
    });
    req.on('timeout', () => req.destroy(new Error('Local server timed out')));
    req.on('error', reject);
    req.end(body);
  });
}

function params(token = subject()) {
  return new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    requested_token_type: 'urn:ietf:params:oauth:token-type:id-jag',
    subject_token_type: 'urn:ietf:params:oauth:token-type:id_token', subject_token: token,
    audience: expected.audience, resource: expected.resource, scope: expected.scope
  });
}

let checks = 0;
function check(name, ok) {
  if (!ok) throw new Error(`Check failed: ${name}`);
  checks++;
  console.log(`PASS: ${name}`);
}
async function reject(name, form, credentials) {
  const result = await call('/as/token.oauth2', form, credentials);
  check(name, [400, 401, 403].includes(result.status) && typeof result.data.error === 'string' && !result.data.access_token);
}

async function main() {
  const result = await call('/as/token.oauth2', params());
  if (result.status !== 200) {
    const code = typeof result.data.error === 'string' && /^[a-z_]+$/.test(result.data.error) ? result.data.error : 'unknown';
    throw new Error(`Positive exchange failed: HTTP ${result.status}, ${code}; inspect protected PF diagnostics`);
  }
  check('live token endpoint returns ID-JAG and N_A', result.data.issued_token_type === 'urn:ietf:params:oauth:token-type:id-jag' && result.data.token_type === 'N_A');
  const jwks = await call('/pf/JWKS');
  check('live PF JWKS is available', jwks.status === 200);
  const verified = verifyIdJag(result.data.access_token, jwks.data, expected);
  check('live managed-key signature and ID-JAG claims verify', verified.signatureVerified && verified.profileClaimsVerified);
  check('live response expiry is bounded', result.data.expires_in > 0 && result.data.expires_in <= 300);
  const claims = JSON.parse(Buffer.from(result.data.access_token.split('.')[1], 'base64url'));
  check('live subject matches authorized fixture', claims.sub === config.authorized_test_subject);

  for (const [name, changes] of Object.entries({
    'wrong subject issuer': { iss: 'https://untrusted.example.test' },
    'wrong subject audience': { aud: 'unrelated-client' },
    'wrong authorized party': { azp: 'unrelated-client' },
    'missing authorized party': { azp: undefined },
    'unauthorized subject': { sub: 'unauthorized-user' },
    'expired subject': { exp: Math.floor(Date.now() / 1000) - 60 },
    'missing subject expiry': { exp: undefined },
    'multiple subject audiences': { aud: [clientId, 'unrelated-client'] }
  })) await reject(name, params(subject(changes)));

  const tampered = subject().split('.');
  const signature = Buffer.from(tampered[2], 'base64url'); signature[0] ^= 1;
  tampered[2] = signature.toString('base64url');
  await reject('invalid subject signature', params(tampered.join('.')));
  for (const name of ['audience', 'resource', 'scope']) {
    const repeated = params(); repeated.append(name, repeated.get(name));
    await reject(`duplicate ${name}`, repeated);
    const missing = params(); missing.delete(name);
    await reject(`missing ${name}`, missing);
  }
  for (const [name, value] of Object.entries({ audience: 'https://unregistered.example.test', resource: 'https://api.example.test/other', scope: 'admin', requested_token_type: 'urn:example:unsupported' })) {
    const changed = params(); changed.set(name, value);
    await reject(`unauthorized ${name}`, changed);
  }
  await reject('missing client authentication', params(), null);
  await reject('wrong client secret', params(), [clientId, 'deliberately-wrong-secret']);
  await reject('disabled compatibility client cannot authenticate', params(), [expected.audience, config.audience_client_secret]);
  console.log(JSON.stringify({ checksPassed: checks, livePingFederate: true, subjectIsLocalFixture: true, downstreamRedemptionTested: false }));
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
