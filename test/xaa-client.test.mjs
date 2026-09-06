import { once } from 'node:events';
import http from 'node:http';
import test from 'node:test';
import assert from 'node:assert/strict';

import { GRANTS, TOKEN_TYPES, XaaClient, XaaError } from '../src/xaa-client.mjs';

function parseRequest(request, body) {
  return {
    method: request.method,
    authorization: request.headers.authorization,
    form: Object.fromEntries(new URLSearchParams(body))
  };
}

async function startServer(handler) {
  const server = http.createServer(handler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const { port } = server.address();
  return { server, baseUrl: `http://127.0.0.1:${port}` };
}

test('performs token exchange and downstream JWT bearer exchange', async (t) => {
  const requests = [];
  const { server, baseUrl } = await startServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requests.push(parseRequest(request, body));
      response.setHeader('content-type', 'application/json');
      if (request.url === '/as/token.oauth2') {
        response.end(JSON.stringify({
          access_token: 'signed-id-jag',
          issued_token_type: TOKEN_TYPES.ID_JAG,
          token_type: 'N_A',
          expires_in: 300
        }));
      } else {
        response.end(JSON.stringify({ access_token: 'target-access-token', token_type: 'Bearer' }));
      }
    });
  });
  t.after(() => server.close());

  const client = new XaaClient({
    pingFederateTokenEndpoint: `${baseUrl}/as/token.oauth2`,
    clientId: 'primary-app-client',
    clientSecret: 'pf-secret',
    downstreamTokenEndpoint: `${baseUrl}/target/token`,
    downstreamClientId: 'target-client',
    downstreamClientSecret: 'target-secret'
  });

  const idJag = await client.getIdJag({
    subjectToken: 'subject-token',
    subjectTokenType: TOKEN_TYPES.REFRESH_TOKEN,
    audience: 'https://api.example.test',
    resource: 'https://api.example.test/reports',
    scope: 'read:reports'
  });
  const target = await client.exchangeIdJag({ assertion: idJag.assertion });

  assert.equal(idJag.assertion, 'signed-id-jag');
  assert.equal(target.access_token, 'target-access-token');
  assert.equal(requests.length, 2);
  assert.equal(requests[0].method, 'POST');
  assert.equal(requests[0].form.grant_type, GRANTS.TOKEN_EXCHANGE);
  assert.equal(requests[0].form.requested_token_type, TOKEN_TYPES.ID_JAG);
  assert.equal(requests[0].form.subject_token, 'subject-token');
  assert.equal(requests[0].form.resource, 'https://api.example.test/reports');
  assert.match(requests[0].authorization, /^Basic /);
  assert.equal(requests[1].form.grant_type, GRANTS.JWT_BEARER);
  assert.equal(requests[1].form.assertion, 'signed-id-jag');
  assert.match(requests[1].authorization, /^Basic /);
});

test('does not send the PingFederate client secret to the downstream server', async (t) => {
  let downstreamForm;
  const { server, baseUrl } = await startServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      downstreamForm = Object.fromEntries(new URLSearchParams(body));
      response.end(JSON.stringify({ access_token: 'target-token' }));
    });
  });
  t.after(() => server.close());

  const client = new XaaClient({
    pingFederateTokenEndpoint: `${baseUrl}/pf`,
    clientId: 'primary-client',
    clientSecret: 'pf-secret',
    downstreamTokenEndpoint: `${baseUrl}/target`
  });
  await client.exchangeJwtAssertion({ assertion: 'id-jag' });

  assert.equal(downstreamForm.client_id, undefined);
  assert.equal(downstreamForm.client_secret, undefined);
  assert.equal(downstreamForm.assertion, 'id-jag');
});

test('generic JWT helper sends its configured legacy token type (mock only)', async (t) => {
  let requestForm;
  const { server, baseUrl } = await startServer((request, response) => {
    let body = '';
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      requestForm = Object.fromEntries(new URLSearchParams(body));
      response.end(JSON.stringify({
        access_token: 'signed-standard-jwt',
        issued_token_type: TOKEN_TYPES.PINGFEDERATE_JWT,
        token_type: 'N_A'
      }));
    });
  });
  t.after(() => server.close());

  const client = new XaaClient({
    pingFederateTokenEndpoint: `${baseUrl}/as/token.oauth2`,
    clientId: 'primary-client',
    clientSecret: 'pf-secret',
    downstreamTokenEndpoint: `${baseUrl}/target/token`
  });

  const result = await client.getJwtAssertion({
    subjectToken: 'subject-access-token',
    subjectTokenType: TOKEN_TYPES.ACCESS_TOKEN,
    audience: 'https://target.example.test',
    scope: 'read:reports'
  });

  assert.equal(result.assertion, 'signed-standard-jwt');
  assert.equal(result.issuedTokenType, TOKEN_TYPES.PINGFEDERATE_JWT);
  assert.equal(requestForm.requested_token_type, TOKEN_TYPES.PINGFEDERATE_JWT);
});

test('ID-JAG redemption requires target client authentication', async () => {
  const client = new XaaClient({
    pingFederateTokenEndpoint: 'https://pf.example.test/token', clientId: 'source', clientSecret: 'secret',
    downstreamTokenEndpoint: 'https://target.example.test/token'
  });
  await assert.rejects(() => client.exchangeIdJag({ assertion: 'fixture' }), /downstream client credentials/);
});

test('rejects missing issued token type and non-assertion token_type', async () => {
  for (const body of [
    { access_token: 'fixture', token_type: 'N_A' },
    { access_token: 'fixture', issued_token_type: TOKEN_TYPES.ID_JAG, token_type: 'Bearer' }
  ]) {
    const client = new XaaClient({
      pingFederateTokenEndpoint: 'https://pf.example.test/token', clientId: 'source', clientSecret: 'secret',
      downstreamTokenEndpoint: 'https://target.example.test/token',
      fetchImpl: async () => new Response(JSON.stringify(body))
    });
    await assert.rejects(() => client.getIdJag({ subjectToken: 'fixture', audience: 'https://target.example.test' }), XaaError);
  }
});

test('OAuth Basic encodes credentials and disables redirect following', async () => {
  const client = new XaaClient({
    pingFederateTokenEndpoint: 'https://pf.example.test/token', clientId: 'source:a b', clientSecret: 's:e+c',
    downstreamTokenEndpoint: 'https://target.example.test/token',
    fetchImpl: async (url, request) => {
      assert.equal(Buffer.from(request.headers.authorization.slice(6), 'base64').toString(), 'source%3Aa+b:s%3Ae%2Bc');
      assert.equal(request.redirect, 'error');
      return new Response(JSON.stringify({ access_token: 'fixture', issued_token_type: TOKEN_TYPES.ID_JAG, token_type: 'N_A' }));
    }
  });
  await client.getIdJag({ subjectToken: 'fixture', audience: 'https://target.example.test' });
});

test('rejects an unexpected issued token type', async (t) => {
  const { server, baseUrl } = await startServer((request, response) => {
    request.resume();
    request.on('end', () => response.end(JSON.stringify({
      access_token: 'not-an-id-jag',
      issued_token_type: TOKEN_TYPES.ACCESS_TOKEN
    })));
  });
  t.after(() => server.close());

  const client = new XaaClient({
    pingFederateTokenEndpoint: `${baseUrl}/pf`,
    clientId: 'client',
    clientSecret: 'secret',
    downstreamTokenEndpoint: `${baseUrl}/target`
  });

  await assert.rejects(
    () => client.getIdJag({
      subjectToken: 'subject',
      audience: 'https://api.example.test'
    }),
    (error) => error instanceof XaaError && error.code === 'unexpected_issued_token_type'
  );
});

test('requires actor token type when actor token is supplied', async () => {
  const client = new XaaClient({
    pingFederateTokenEndpoint: 'http://127.0.0.1:1/pf',
    clientId: 'client',
    clientSecret: 'secret',
    downstreamTokenEndpoint: 'http://127.0.0.1:1/target'
  });

  await assert.rejects(
    () => client.getIdJag({
      subjectToken: 'subject',
      audience: 'https://api.example.test',
      actorToken: 'actor'
    }),
    /actorTokenType is required/
  );
});
