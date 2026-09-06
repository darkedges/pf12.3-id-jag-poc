export const GRANTS = Object.freeze({
  TOKEN_EXCHANGE: 'urn:ietf:params:oauth:grant-type:token-exchange',
  JWT_BEARER: 'urn:ietf:params:oauth:grant-type:jwt-bearer'
});

export const TOKEN_TYPES = Object.freeze({
  ACCESS_TOKEN: 'urn:ietf:params:oauth:token-type:access_token',
  ID_TOKEN: 'urn:ietf:params:oauth:token-type:id_token',
  REFRESH_TOKEN: 'urn:ietf:params:oauth:token-type:refresh_token',
  JWT: 'urn:ietf:params:oauth:token-type:jwt',
  // PingFederate 12.x documents this legacy JWT token-type URI.
  PINGFEDERATE_JWT: 'urn:params:oauth:token-type:jwt',
  ID_JAG: 'urn:ietf:params:oauth:token-type:id-jag'
});

export class XaaError extends Error {
  constructor(message, { code = 'xaa_error', status, details, cause } = {}) {
    super(message, { cause });
    this.name = 'XaaError';
    this.code = code;
    this.status = status;
    this.details = details;
  }
}

function requiredString(name, value) {
  if (typeof value !== 'string' || value.trim() === '') {
    throw new TypeError(`${name} must be a non-empty string`);
  }
  return value;
}

function optionalString(name, value) {
  if (value === undefined || value === null) return undefined;
  return requiredString(name, value);
}

function appendIfPresent(form, name, value) {
  if (value !== undefined && value !== null && value !== '') {
    form.set(name, String(value));
  }
}

function assertHttpsInProduction(endpoint) {
  const url = new URL(endpoint);
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TypeError(`OAuth endpoint must use HTTP or HTTPS: ${url.href}`);
  }
  if (url.protocol !== 'https:' && process.env.NODE_ENV === 'production') {
    throw new TypeError(`HTTPS is required for ${url.href} when NODE_ENV=production`);
  }
  return url.href;
}

function basicAuth(clientId, clientSecret) {
  // OAuth Basic credentials are form-encoded individually before Base64.
  const encode = value => new URLSearchParams({ v: value }).toString().slice(2);
  const value = Buffer.from(`${encode(clientId)}:${encode(clientSecret)}`, 'utf8').toString('base64');
  return `Basic ${value}`;
}

function safeErrorDetails(body) {
  if (!body || typeof body !== 'object') return undefined;
  const details = {};
  for (const key of ['error', 'error_description', 'error_uri']) {
    if (typeof body[key] === 'string') details[key] = body[key];
  }
  return Object.keys(details).length > 0 ? details : undefined;
}

async function readResponseBody(response) {
  const text = await response.text();
  if (!text) return {};
  try {
    return JSON.parse(text);
  } catch {
    return { _raw: text.slice(0, 500) };
  }
}

export class XaaClient {
  constructor({
    pingFederateTokenEndpoint,
    clientId,
    clientSecret,
    downstreamTokenEndpoint,
    downstreamClientId,
    downstreamClientSecret,
    timeoutMs = 10_000,
    fetchImpl = globalThis.fetch
  }) {
    this.pingFederateTokenEndpoint = assertHttpsInProduction(
      requiredString('pingFederateTokenEndpoint', pingFederateTokenEndpoint)
    );
    this.clientId = requiredString('clientId', clientId);
    this.clientSecret = requiredString('clientSecret', clientSecret);
    this.downstreamTokenEndpoint = assertHttpsInProduction(
      requiredString('downstreamTokenEndpoint', downstreamTokenEndpoint)
    );
    this.downstreamClientId = optionalString('downstreamClientId', downstreamClientId);
    this.downstreamClientSecret = optionalString('downstreamClientSecret', downstreamClientSecret);

    if (!Number.isInteger(timeoutMs) || timeoutMs <= 0) {
      throw new TypeError('timeoutMs must be a positive integer');
    }
    if (typeof fetchImpl !== 'function') {
      throw new TypeError('fetchImpl must be a function');
    }
    if (this.downstreamClientSecret && !this.downstreamClientId) {
      throw new TypeError('downstreamClientId is required when downstreamClientSecret is provided');
    }

    this.timeoutMs = timeoutMs;
    this.fetchImpl = fetchImpl;
  }

  /**
   * Ask PingFederate to mint an ID-JAG through RFC 8693 token exchange.
   *
   * `subjectTokenType` is deliberately explicit at the call site. PingFederate
   * deployments commonly use a refresh token for this profile, while other
   * token-exchange policies accept an access token or JWT.
   */
  async getIdJag({
    subjectToken,
    subjectTokenType = TOKEN_TYPES.ACCESS_TOKEN,
    audience,
    resource,
    scope,
    actorToken,
    actorTokenType
  }) {
    return this.#getAssertion({
      subjectToken,
      subjectTokenType,
      audience,
      resource,
      scope,
      actorToken,
      actorTokenType,
      requestedTokenType: TOKEN_TYPES.ID_JAG,
      responseName: 'ID-JAG'
    });
  }

  /**
   * Generic JWT exchange helper retained for separately configured deployments.
   * Its token-type default is historical and is NOT verified against a JWT ATM.
   * Use getIdJag() for the custom generator shipped in this repository.
   */
  async getJwtAssertion({
    subjectToken,
    subjectTokenType = TOKEN_TYPES.ACCESS_TOKEN,
    audience,
    resource,
    scope,
    actorToken,
    actorTokenType,
    requestedTokenType = TOKEN_TYPES.PINGFEDERATE_JWT
  }) {
    return this.#getAssertion({
      subjectToken,
      subjectTokenType,
      audience,
      resource,
      scope,
      actorToken,
      actorTokenType,
      requestedTokenType,
      responseName: 'JWT'
    });
  }

  async #getAssertion({
    subjectToken,
    subjectTokenType,
    audience,
    resource,
    scope,
    actorToken,
    actorTokenType,
    requestedTokenType,
    responseName
  }) {
    requiredString('subjectToken', subjectToken);
    requiredString('subjectTokenType', subjectTokenType);
    requiredString('audience', audience);
    requiredString('requestedTokenType', requestedTokenType);
    optionalString('resource', resource);
    optionalString('scope', scope);

    if (actorToken !== undefined && actorTokenType === undefined) {
      throw new TypeError('actorTokenType is required when actorToken is provided');
    }
    if (actorTokenType !== undefined && actorToken === undefined) {
      throw new TypeError('actorToken is required when actorTokenType is provided');
    }

    const form = new URLSearchParams({
      grant_type: GRANTS.TOKEN_EXCHANGE,
      subject_token: subjectToken,
      subject_token_type: subjectTokenType,
      requested_token_type: requestedTokenType,
      audience
    });
    appendIfPresent(form, 'resource', resource);
    appendIfPresent(form, 'scope', scope);
    appendIfPresent(form, 'actor_token', actorToken);
    appendIfPresent(form, 'actor_token_type', actorTokenType);

    const body = await this.#postForm(
      this.pingFederateTokenEndpoint,
      form,
      basicAuth(this.clientId, this.clientSecret)
    );

    if (typeof body.access_token !== 'string' || body.access_token.length === 0) {
      throw new XaaError(`PingFederate did not return a ${responseName} assertion`, {
        code: 'invalid_token_exchange_response',
        details: safeErrorDetails(body)
      });
    }
    if (body.issued_token_type !== requestedTokenType) {
      throw new XaaError('PingFederate returned an unexpected token type', {
        code: 'unexpected_issued_token_type',
        details: { issued_token_type: body.issued_token_type }
      });
    }
    if (requestedTokenType === TOKEN_TYPES.ID_JAG && body.token_type !== 'N_A') {
      throw new XaaError('ID-JAG response must have token_type N_A', { code: 'invalid_token_exchange_response' });
    }

    return {
      assertion: body.access_token,
      issuedTokenType: body.issued_token_type,
      expiresIn: body.expires_in,
      raw: body
    };
  }

  /**
   * Exchange the ID-JAG at the target authorization server using RFC 7523.
   * The target server may require a separate OAuth client authentication pair.
   */
  async exchangeIdJag({ assertion, scope }) {
    if (!this.downstreamClientId || !this.downstreamClientSecret) {
      throw new TypeError('ID-JAG redemption requires separately registered downstream client credentials');
    }
    return this.exchangeAssertion({ assertion, scope });
  }

  /** Exchange a standard JWT assertion at the target authorization server. */
  async exchangeJwtAssertion({ assertion, scope }) {
    return this.exchangeAssertion({ assertion, scope });
  }

  /** Exchange either an ID-JAG or a standard JWT using RFC 7523. */
  async exchangeAssertion({ assertion, scope }) {
    requiredString('assertion', assertion);
    optionalString('scope', scope);

    const form = new URLSearchParams({
      grant_type: GRANTS.JWT_BEARER,
      assertion
    });
    appendIfPresent(form, 'scope', scope);

    let authorization;
    if (this.downstreamClientId && this.downstreamClientSecret) {
      authorization = basicAuth(this.downstreamClientId, this.downstreamClientSecret);
    } else if (this.downstreamClientId) {
      // A public target client can be identified without client authentication.
      form.set('client_id', this.downstreamClientId);
    }

    return this.#postForm(this.downstreamTokenEndpoint, form, authorization);
  }

  async #postForm(endpoint, form, authorization) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers = { 'content-type': 'application/x-www-form-urlencoded' };
      if (authorization) headers.authorization = authorization;

      let response;
      try {
        response = await this.fetchImpl(endpoint, {
          method: 'POST',
          headers,
          body: form.toString(),
          redirect: 'error',
          signal: controller.signal
        });
      } catch (error) {
        const code = error?.name === 'AbortError' ? 'request_timeout' : 'request_failed';
        throw new XaaError('OAuth token request failed', { code, cause: error });
      }

      const body = await readResponseBody(response);
      if (!response.ok) {
        throw new XaaError(`OAuth token request returned HTTP ${response.status}`, {
          code: body.error || 'oauth_request_failed',
          status: response.status,
          details: safeErrorDetails(body)
        });
      }
      return body;
    } finally {
      clearTimeout(timer);
    }
  }
}
