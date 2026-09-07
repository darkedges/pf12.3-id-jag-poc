# Verification record

Inspected local installation: `C:/development/pingfed/pingfederate/12.3.3`.

## Confirmed against real 12.3.3 classes

- `TokenGenerator.generateToken(TokenContext)` is available.
- `TokenGeneratorOutputGenerationStrategy.generate()` sets mapped subject attributes; its newly created `TokenContext` has empty input parameters.
- `StringSecurityToken` accepts `(tokenType, data)` and carries an expiry date.
- The real `SecurityTokenTokenResponse` serializer returns the compact JWT unchanged, the custom requested token URI, `N_A`, and expiry seconds.
- The real `TokenExchangeRequest` parses the ID-JAG type. The real resource selector and generator-group mapping select the custom generator. Tests inject a manager containing fixture configuration; no running admin configuration is implied.
- The SDK exposes `JwksEndpointKeyAccessor` and its current-RS256-key method. The plugin uses that public accessor; offline tests inject an ephemeral signing key instead.
- The real `TokenExchangeAudienceParameterValidator` rejects an audience without a corresponding local OAuth client and accepts the target issuer when a fixture client has that exact ID (without `openid` scope). Bytecode identifies the rejection as `invalid_target`.

Run `generator/build.ps1` for 26 checks, including signature/claims, unique JWT IDs, expiry bounds and rejection of mismatched clients/destinations/scopes and repeated request parameters. The proof invokes PF's private response adapter reflectively in **test code only**. The plugin does not use reflection. A legacy Javassist warning from the provided PF libraries can appear under JDK 11.

Maven packaging was verified separately using the existing local Maven cache. Maven does not execute the standalone proof runner.

## Live verification: 2026-09-07 Australia/Sydney

Container `pingfederate-xaa`, admin `https://localhost:9999`, runtime `https://localhost:9031`. Admin API reports **12.3.3.1**. The JAR was deployed to `/opt/out/instance/server/default/deploy`, the container restarted, and its descriptor discovered through the Admin API.

Terraform applied eight scoped resources. The follow-up `plan -detailed-exitcode` returned **0 / No changes**. Four mocked Terraform configuration tests pass. The base Docker files and global OAuth/expression/key settings were preserved. The optional Compose overlay has not been exercised.

`node scripts/live-local-proof.mjs` passes **27 checks against the real HTTP endpoint**:

- Successful token exchange returns a compact ID-JAG, correct issued type, `N_A`, and bounded expiry.
- Its RS256 signature verifies using PF's live JWKS and its subject/client/audience/resource/scope claims match the test configuration.
- Wrong issuer/audience/authorized party, absent authorized party, unauthorized subject, expired or expiry-less subject tokens, multiple subject audiences and invalid signatures are rejected.
- Duplicate or missing audience/resource/scope, unauthorized destinations/scopes/token types, missing client authentication and wrong secrets are rejected.
- The disabled issuer-URL compatibility client supports audience routing but cannot authenticate.

The successful subject token is signed with a local fixture key explicitly trusted by JWT Token Processor 2.0. This exercises inbound cryptographic validation, not a real OIDC login. The runner displays decoded ID-JAG headers and claims by default, but does not print the compact subject token, compact ID-JAG, signature, client secret or PF private key. Use `--no-show-jwt` or `XAA_SHOW_JWT=false` when claims should remain hidden. PF-managed key retrieval and publication are now confirmed live.

The generator now receives six mapped attributes, including the actual `HttpRequest` context object. It checks repeated parameters in Java. The server rejected expression-based mappings during initial configuration, and no global expression setting was enabled. PF also required a default mapping inside the resource-selected group; no global default group was configured.

## Remaining integration scope

- Real subject-token issuance through the intended OIDC provider and production subject resolution/entitlements.
- Downstream AS trust/registration, ID-JAG acceptance, access-token issuance and replay enforcement.
- Multi-node deployment, key rotation behavior and full agreed-draft conformance beyond this fixed-destination proof.

`node --test` separately passes 24 tests: eight mocked client/protocol checks and sixteen smoke-verifier checks using locally signed RSA fixtures, including tampering and invalid-claim rejection. These unit tests are distinct from the live runner and do not establish a native JWT-ATM flow.
