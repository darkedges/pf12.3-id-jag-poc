# Terraform-managed XAA proof on PingFederate 12.3.3

Tested against the local container reporting **12.3.3.1**. Eight resources are managed: the JWT subject processor, exchange policy, requesting client, disabled audience compatibility client, custom generator instance, generator group, generator mapping, and one common scope (one resource per scope if expanded).

The pinned `pingidentity/pingfederate` 1.9.0 provider supports PF 12.3 but does **not** implement the generator-instance/group resources referred to in some of its examples. `Mastercard/restapi` 3.0.0 manages those two API endpoints and individual scope entries through normal Terraform CRUD/refresh. No `local-exec` provisioners or global expression settings are used. Commit `.terraform.lock.hcl`.

## Existing local setup

The plugin is already deployed in `pingfederate-xaa`, and Terraform has applied the configuration. Preserve `terraform/terraform.tfstate` and `.local/local.tfvars.json`; they are ignored by Git but contain sensitive material. Do not recreate the state and apply again to the same server: import existing resources if state is lost.

From the repository root, enter the admin password without saving it in source or shell history:

```powershell
$credential = Get-Credential -UserName administrator
$env:TF_VAR_admin_username = $credential.UserName
$env:TF_VAR_admin_password = $credential.GetNetworkCredential().Password
try {
  terraform '-chdir=terraform' init -input=false
  terraform '-chdir=terraform' plan '-var-file=../.local/local.tfvars.json' '-out=../.local/xaa.tfplan'
  # Review the plan before applying it:
  terraform '-chdir=terraform' apply '../.local/xaa.tfplan'
} finally {
  Remove-Item Env:TF_VAR_admin_username, Env:TF_VAR_admin_password -ErrorAction SilentlyContinue
}
node scripts/live-local-proof.mjs
```

The admin password variable is ephemeral (Terraform 1.10+), so it is not stored in state or saved plans. OAuth client secrets **are** stored in state; sensitive marking only hides their display. Use encrypted, access-controlled remote state and secret-manager-injected variables for shared use. Keep debug logging off. Secure `.local/` with user-only filesystem permissions, especially on Windows where POSIX file modes are not an ACL guarantee.

## Reproduce on a fresh local test server

1. Build `generator/build.ps1` and run its proof checks.
2. Deploy the JAR into `server/default/deploy` and restart PF. For the included Docker setup, the optional `docker-compose.xaa.yml` overlays a read-only JAR mount. Build the JAR **before** running `docker compose -f docker-compose.yml -f docker-compose.xaa.yml up -d`. Wait until the admin API is ready; container start does not mean PF has finished initialization. The overlay is provided but was not used in the live run.
3. Run `node scripts/create-local-fixture.mjs`. It creates a disposable RSA subject-signing key and independent random client secrets under `.local/`; repeat runs preserve existing keys/secrets.
4. Initialize, review the plan, and apply using the commands above. On a fresh server the plan should contain eight additions and no existing-resource changes.
5. Run `node scripts/live-local-proof.mjs` for the live issuance and negative checks; no tokens or credentials are printed. The fixture is **not** a real OIDC login.

For real issuer testing, use `terraform.tfvars.example` with public JWKS and an explicitly authorized subject. This deliberately narrow policy requires `azp` to equal the requesting client, even though some real ID tokens omit that optional claim. It also accepts only a single subject-token audience. Do not weaken those checks just to accept unrelated clients' tokens.

The configured target issuer/resource use reserved example domains. Terraform does not create a downstream AS or target client. Target trust, client registration, subject resolution and replay protection remain separate work.

## TLS, signing and configuration boundaries

- TLS verification defaults to enabled. Supply `ca_certificate_file` for a private CA. The fixture explicitly enables a localhost-only exception; never use that exception remotely.
- PF's existing dynamic OAuth signing keys are used and published at `/pf/JWKS`. Terraform does not replace global key settings or put PF private keys into state.
- The compatibility client ID is the exact downstream issuer URL. It remains **disabled**, uses an independent unused secret, and has only `ACCESS_TOKEN_VALIDATION` because the native provider requires a nonempty grant list. Live issuance succeeds with it disabled, and an authentication attempt using it is rejected.
- The group has a required default **mapping inside that group**. No global default generator group is configured. Requests must explicitly include the intended resource and ID-JAG type.
- Request parameters are read by Java from mapped Context `HttpRequest`; authenticated client identity comes separately from Context `ClientId`. No OGNL enablement is required.
- Authorization is one named subject plus validated issuer/client binding and scope ceiling. Replace this test policy with real entitlements before production.

## Validation and import

```powershell
terraform '-chdir=terraform' fmt -check -recursive
terraform '-chdir=terraform' validate
terraform '-chdir=terraform' test
```

Terraform tests use mocked providers and do not prove server behavior. The live runner does. After apply, a plan with `-detailed-exitcode` should exit `0` for no changes, `2` for a change, or `1` for an error.

If taking over an existing configuration, match its IDs/settings and import before applying. Example addresses/IDs for this setup (supply the same variables and admin environment as above):

```powershell
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' restapi_object.generator /sp/tokenGenerators/xaaIdJag
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' restapi_object.generator_group /oauth/tokenExchange/generator/groups/xaaGroup
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' pingfederate_idp_token_processor.subject xaaSubjectJwt
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' pingfederate_oauth_token_exchange_processor_policy.xaa xaaPolicy
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' pingfederate_oauth_client.requesting xaa-primary-client
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' pingfederate_oauth_client.audience https://target.example.test
terraform '-chdir=terraform' import '-var-file=../.local/local.tfvars.json' pingfederate_oauth_token_exchange_token_generator_mapping.xaa 'xaaPolicy|xaaIdJag'
```

The scope must also be imported at address `restapi_object.scope["read:reports"]` with ID `/oauth/authServerSettings/scopes/commonScopes/read:reports`; pass the literal address using your shell's native argument-quoting rules. Import syntax is provider-documented but was not exercised against a second state during this run.

Do not run `destroy` casually: it removes the managed scope, clients and trust/policies. It does not remove the deployed JAR or local fixture files. Any teardown should first be reviewed as a destroy plan against the intended test server.

Sources: [Ping provider and supported server versions](https://registry.terraform.io/providers/pingidentity/pingfederate/1.9.0/docs), [REST resource CRUD and import](https://registry.terraform.io/providers/Mastercard/restapi/3.0.0/docs/resources/object).
