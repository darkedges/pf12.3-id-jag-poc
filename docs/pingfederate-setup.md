# Custom ID-JAG on PingFederate 12.3.3

## Scope

One PF client, one downstream authorization server, one resource, RS256, and a maximum 300-second lifetime. Each destination/client pair gets its own generator instance. JWT Token Processor 2.0 validates issuer, signature, audience and expiry; the processor policy additionally requires an authorized subject and matching `azp`. No custom inbound processor is needed for this narrow proof. The live run on 12.3.3.1 uses a locally signed subject fixture, not a real OIDC login. [Terraform setup and commands](../terraform/README.md) are the executable configuration.

This is a custom implementation of a subset of [ID-JAG draft-04](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-identity-assertion-authz-grant-04), not native 12.3.3 product support or a claim of full conformance. Multi-tenant resolution, actor tokens, RAR, refresh-token input and dynamic client registration are outside this proof.

## 1. Install and configure the generator

Build with `generator/build.ps1`. Deploy only `generator/target/xaa-id-jag-generator.jar` into the test server's `server/default/deploy` and restart using your normal service procedure. Replicate the JAR to all relevant nodes. Its descriptor is `PF-INF/token-generators`; this is not an IdP authentication adapter.

Create a token-generator instance of type **DarkEdges ID-JAG Generator (12.3.3 proof)**. Terraform uses instance ID `xaaIdJag`.

| Field | Example | Meaning |
| --- | --- | --- |
| Issuer | `https://pf.example.test` | Exact PF issuer trusted by the target |
| Requesting Client ID | `xaa-primary-client` | Allowed authenticated PF client |
| Target Issuer | `https://target.example.test` | ID-JAG audience: target AS issuer, not its API URI |
| Target Client ID | `target-client` | Client registration at the target AS |
| Resource | `https://api.example.test/reports` | Fixed API URI and generator-group selector |
| Allowed Scopes | `read:reports` | Scope ceiling; user authorization is additionally required |
| Lifetime Seconds | `300` | Also capped to validated subject-token expiry |

The plugin obtains `getCurrentRsaKey("RS256")` through PF's `JwksEndpointKeyAccessor` per issuance. Its returned `kid` must exist at the trusted JWKS URL. Private keys stay with PF. Retrieval and publication were verified live using this server's existing dynamic OAuth keys; global key settings were not changed.

## 2. Inbound validation and TEPP

Create a JWT Token Processor 2.0 instance accepting the actual ID-token issuer. Set expected audience to the requesting client's OIDC registration and validate signature/time claims. Expose `sub`, `exp` and validated client binding. For this proof, restrict the ID-token audience to one intended client and enforce any `azp` consistency before mapping `subject_client_id`.

Create a Token Exchange Processor Policy, `xaaPolicy`, with this mapping:

```text
subject_token_type = urn:ietf:params:oauth:token-type:id_token
subject token processor = the JWT Token Processor 2.0 instance above
```

The generator now has six attributes. The TEPP exposes core `subject` plus `subject_client_id`, `subject_exp` and `approved_scope`; the generator mapping supplies the two request-context attributes directly.

| Generator attribute | Required source |
| --- | --- |
| `sub` | Validated subject, resolved to the identity used by the target's SSO trust |
| `subject_client_id` | Validated subject-token audience/authorized party, not a request parameter |
| `subject_exp` | Validated subject-token `exp`, Unix seconds |
| `authenticated_client_id` | Context **Client ID** (`context.ClientId`) |
| `http_request` | Context **HTTP Request**, API source `CONTEXT` with value `HttpRequest`; retain the actual servlet request object |
| `approved_scope` | Trusted user/client/destination authorization policy or entitlement lookup, joined into one space-delimited string |

Do not copy requested scope into `approved_scope`. A fixed value is appropriate only for an explicitly authorized test user/client pair constrained by issuance criteria. Requested scopes must fit both the approved scope set and the configured ceiling. Authentication alone does not establish cross-application authorization.

The Java generator reads `audience`, `resource` and `scope` using `getParameterValues()` on the mapped servlet request and rejects missing or repeated parameters. It separately validates the authenticated client from Context `ClientId`; request parameters are not used to establish caller identity. This direct object mapping was verified live. Expression mappings were rejected by this server's configuration, so no OGNL or global expression enablement is required.

On the PF OAuth client enable **Token Exchange**, require confidential-client authentication, and assign `xaaPolicy`. Terraform creates `xaa-primary-client` with only that grant and the allowed scopes. Its policy authorizes exactly one test subject and requires `azp` to match the requesting client. The generator also checks the validated single-valued audience against the authenticated client. This proof cannot exchange arbitrary bearer tokens issued to unrelated apps.

## 3. Route the custom type

**12.3.3 compatibility prerequisite:** its token-exchange audience validator looks up every `audience` value as a **local PF OAuth client ID**, even for a custom requested token type. An unknown value fails with `invalid_target` before the generator runs. To retain ID-JAG's target-issuer audience, add a separate local compatibility client whose ID is exactly `https://target.example.test` (the configured Target Issuer). Terraform keeps it **disabled** with an independent random secret and only `ACCESS_TOKEN_VALIDATION` (the provider requires a nonempty grant list). Live issuance succeeds with it disabled; authentication using it is rejected. It must not be used to obtain tokens or reuse either application's credentials.

These are three distinct registrations: `xaa-primary-client` authenticates the exchange at PF; the issuer-URL compatibility registration satisfies PF's audience lookup; `target-client` must authenticate redemption at the downstream AS (not provisioned here). Keep `openid` out of this proof's requested scopes; it triggers additional OIDC policy checks.

In **Applications > Token Exchange > Generator Groups**, create `xaaGroup` with the exact Resource URI from the generator settings. Add:

```text
urn:ietf:params:oauth:token-type:id-jag -> xaaIdJag
```

Select this mapping as the default **inside the group**, which PF requires. Do not make the group a global default. Send `resource` and `requested_token_type` explicitly. Avoid mappings that collide with other groups/ATMs. Resource selection and full token-endpoint routing were verified live.

In **Applications > Token Exchange > Token Generator Mappings**, select source `xaaPolicy` and target `xaaIdJag`, map all six attributes, and enforce the approved user/client/destination combination. The Terraform implementation puts subject/`azp` issuance criteria on the TEPP mapping and fixed destination/scope checks in the generator.

PF 12.3.3 sets generator subject attributes but does not populate its input parameters on this path. Relying on `getInParameters()` for client identity would therefore be incorrect.

Sources: [generator groups](https://docs.pingidentity.com/pingfederate/12.3/administrators_reference_guide/pf_creating_token_exchange_generator_groups.html), [generator mappings](https://docs.pingidentity.com/pingfederate/12.3/administrators_reference_guide/pf_mapping_token_exchange_attributes_token_generator_attributes.html).

## 4. Request and verify

The Node `getIdJag()` method sends this to `/as/token.oauth2` with PF client authentication:

```text
grant_type=urn:ietf:params:oauth:grant-type:token-exchange
requested_token_type=urn:ietf:params:oauth:token-type:id-jag
subject_token=<real ID token from the configured issuer>
subject_token_type=urn:ietf:params:oauth:token-type:id_token
audience=https://target.example.test
resource=https://api.example.test/reports
scope=read:reports
```

The generator returns `StringSecurityToken(TYPE, compactJwt)`. PF's actual 12.3.3 serializer has been exercised: it returns the unchanged compact JWT in `access_token`, the ID-JAG URI in `issued_token_type`, `token_type=N_A`, and `expires_in`. No Base64 wrapper is needed.

Use `.env.example` and `scripts/smoke-id-jag.mjs` to verify a real response without printing tokens. It defaults to issuance/signature verification only. Enable `XAA_REDEEM=true` once the target registration and acceptance policy exist.

## 5. Receiving server

The downstream AS must enforce the agreed ID-JAG profile: issuer/key trust, JWT type, subject resolution, audience, client binding to its authenticated caller, time constraints, authorized resource/scopes and replay prevention. This proof's client uses separate downstream Basic credentials. JWT ID uniqueness at issuance does not prevent replay; the receiver needs atomic replay tracking across nodes.

If the downstream AS is also PF 12.3.3, its JWT-bearer-grant path needs a separate implementation/integration review. Adding a TEPP processor there does not automatically add ID-JAG enforcement to its RFC 7523 path.
