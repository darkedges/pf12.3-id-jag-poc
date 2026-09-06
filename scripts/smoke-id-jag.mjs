import { createPublicKey, verify } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { XaaClient, TOKEN_TYPES } from '../src/xaa-client.mjs';

function requireValue(env, name) {
  if (typeof env[name] !== 'string' || !env[name].trim()) throw new Error(`Set ${name}`);
  return env[name];
}
function httpsUrl(value) {
  const u = new URL(value);
  if (u.protocol !== 'https:' || u.username || u.password || u.hash) throw new Error('An HTTPS URL is required');
  return u.href;
}
function check(ok, message) { if (!ok) throw new Error(message); }

// Diagnostic for this fixed-destination proof, not a resource-AS implementation.
export function verifyIdJag(assertion, jwks, expected, now = Math.floor(Date.now() / 1000)) {
  check(typeof assertion === 'string' && assertion.length < 32768, 'Invalid assertion size');
  const parts = assertion.split('.');
  check(parts.length === 3 && parts.every(p => /^[A-Za-z0-9_-]+$/.test(p)), 'Expected a compact JWS without a Base64 wrapper');
  const header = JSON.parse(Buffer.from(parts[0], 'base64url').toString());
  check(header && header.alg === 'RS256' && header.typ === 'oauth-id-jag+jwt'
    && typeof header.kid === 'string' && header.kid.length > 0 && header.crit === undefined,
  'Unexpected JOSE header');
  check(Array.isArray(jwks?.keys), 'Expected JWKS keys');
  const matches = jwks.keys.filter(k => k.kid === header.kid && k.kty === 'RSA'
    && (!k.use || k.use === 'sig') && (!k.alg || k.alg === 'RS256')
    && (!k.key_ops || k.key_ops.includes('verify')));
  check(matches.length === 1, 'Signing key is absent or ambiguous in configured JWKS');
  const key = createPublicKey({ key: matches[0], format: 'jwk' });
  check(key.asymmetricKeyDetails?.modulusLength >= 2048, 'RSA key is too small');
  check(verify('RSA-SHA256', Buffer.from(`${parts[0]}.${parts[1]}`), key,
    Buffer.from(parts[2], 'base64url')), 'JWT signature failed');
  const c = JSON.parse(Buffer.from(parts[1], 'base64url').toString());
  check(c && c.iss === expected.issuer && c.aud === expected.audience, 'Issuer/audience mismatch');
  check(c.client_id === expected.clientId && c.resource === expected.resource, 'Client/resource mismatch');
  check(typeof c.sub === 'string' && c.sub.length > 0 && typeof c.jti === 'string' && c.jti.length > 0,
    'Missing subject or replay identifier');
  check(Number.isSafeInteger(c.iat) && Number.isSafeInteger(c.exp) && c.exp > now
    && c.iat <= now + 30 && c.exp > c.iat && c.exp - c.iat <= 300, 'Invalid assertion lifetime');
  check(c.nbf === undefined || (Number.isSafeInteger(c.nbf) && c.nbf <= now + 30), 'Assertion is not yet valid');
  check(typeof c.scope === 'string' && c.scope.split(' ').sort().join(' ') === expected.scope.split(' ').sort().join(' '),
    'Scope mismatch');
  return { signatureVerified: true, profileClaimsVerified: true, expiresIn: c.exp - now };
}

async function main(env) {
  const endpoint = httpsUrl(requireValue(env, 'PF_TOKEN_ENDPOINT'));
  const expected = {
    issuer: requireValue(env, 'PF_ISSUER'), audience: requireValue(env, 'TARGET_ISSUER'),
    clientId: requireValue(env, 'TARGET_CLIENT_ID'), resource: requireValue(env, 'TARGET_RESOURCE'),
    scope: requireValue(env, 'XAA_SCOPE')
  };
  const redeem = env.XAA_REDEEM === 'true';
  const client = new XaaClient({
    pingFederateTokenEndpoint: endpoint, clientId: requireValue(env, 'PF_CLIENT_ID'),
    clientSecret: requireValue(env, 'PF_CLIENT_SECRET'),
    downstreamTokenEndpoint: redeem ? httpsUrl(requireValue(env, 'TARGET_TOKEN_ENDPOINT')) : endpoint,
    downstreamClientId: expected.clientId,
    downstreamClientSecret: redeem ? requireValue(env, 'TARGET_CLIENT_SECRET') : undefined
  });
  const result = await client.getIdJag({
    subjectToken: requireValue(env, 'SUBJECT_TOKEN'),
    subjectTokenType: env.SUBJECT_TOKEN_TYPE || TOKEN_TYPES.ID_TOKEN,
    audience: expected.audience, resource: expected.resource, scope: expected.scope
  });
  const response = await fetch(httpsUrl(requireValue(env, 'PF_JWKS_URI')), {
    redirect: 'error', signal: AbortSignal.timeout(10000)
  });
  check(response.ok, 'Configured JWKS endpoint request failed');
  const proof = verifyIdJag(result.assertion, await response.json(), expected);
  if (redeem) {
    const target = await client.exchangeIdJag({ assertion: result.assertion });
    check(typeof target.access_token === 'string' && target.access_token.length > 0
      && typeof target.token_type === 'string', 'Target did not return an access token');
    proof.targetAccessTokenReceived = true;
  }
  console.log(JSON.stringify(proof, null, 2));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main(process.env).catch(error => {
    // Suppress remote bodies, parser errors and URLs that might reflect credentials.
    console.error(error.name === 'XaaError' ? 'OAuth request failed; inspect protected server diagnostics' :
      'Smoke test failed; check configuration, TLS trust, signing keys and assertion claims');
    process.exitCode = 1;
  });
}
