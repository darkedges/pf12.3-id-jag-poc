# PingFederate 12.3.3 custom ID-JAG generator

This project implements an ID-JAG token-generator proof for PingFederate **12.3.3**, Terraform configuration, and a Node client for its RFC 8693 / RFC 7523 flow. Live issuance is verified on the local server reporting **12.3.3.1**: the custom generator signs an ID-JAG with PF-managed keys and its signature verifies against PF's published JWKS.

The earlier recommendation to replace ID-JAG with a JWT ATM flow was premature. This implementation uses **Token Exchange Generator Groups and Token Generator Mappings** for the outbound assertion. The historical generic JWT client helper is retained, but its legacy token-type default is not a verified PF ATM configuration.

## Build and verify

The root `Makefile` provides the common tasks below. On Windows, use GNU Make from Chocolatey, Scoop or Git for Windows.

```text
make help
make build          # Java plugin plus 26 offline proof checks
make test           # Node and Terraform tests
make check          # Build, tests, formatting, validation and Compose syntax
make fixture        # Disposable local fixture under ignored .local/
make live-proof     # Live local token endpoint proof
```

Decoded JWT output and terminal colors are enabled by default. The scripts print the issued ID-JAG header and body as colored attribute/value pairs. The compact token and signature are never printed:

```powershell
node scripts/live-local-proof.mjs
make live-proof
```

Use `--no-show-jwt` or `XAA_SHOW_JWT=false` to hide decoded claims. Set `XAA_COLOR=never` for plain output. `XAA_COLOR=always` is available for explicit scripting clarity.

Credentialed Terraform tasks require `TF_VAR_admin_password` in the environment and use `.local/local.tfvars.json` by default. Review the saved plan before `make terraform-apply`:

```powershell
make terraform-init
make terraform-plan
make terraform-apply
```

Override paths when needed, for example `make java-build PF_INSTALL_DIR=C:/path/to/pingfederate/12.3.3` or `make terraform-plan TFVARS=.local/staging.tfvars.json TFPLAN=.local/staging.tfplan`.

```powershell
.\generator\build.ps1 -PfInstallDir C:\development\pingfed\pingfederate\12.3.3
node --test
```

The PowerShell build needs JDK 11+ and the local PF installation. It produces `generator/target/xaa-id-jag-generator.jar` and runs a separate Java proof against the **actual PF 12.3.3 classes**, without downloading dependencies. Maven packaging also works:

```powershell
mvn -f generator/pom.xml '-Dpf.install.dir=C:/development/pingfed/pingfederate/12.3.3' package
```

Maven packages the plugin; `build.ps1` runs the proof suite in `generator/src/proof/java`. PF libraries and proof classes are not included in the plugin JAR.

## Exercise a real server

Start with [the Terraform guide](terraform/README.md) for the already-applied local setup and reproducible deployment. The local test runner uses an explicitly trusted fixture issuer, not a real user login:

```powershell
node scripts/live-local-proof.mjs
```

For real subject-token testing, follow [the 12.3.3 setup guide](docs/pingfederate-setup.md), configure `.env` using `.env.example`, provide a real subject token, then run (Node 20.6+ for `--env-file`):

```powershell
node --env-file=.env scripts/smoke-id-jag.mjs
```

The script requests the ID-JAG, verifies RS256 against the explicitly configured PF JWKS URL, and checks its claims. It displays the decoded issued JWT by default, without printing the compact token or signature. Use `--no-show-jwt` when claims should remain hidden. With `XAA_REDEEM=true`, it also attempts redemption using the separate target registration. For a local CA, set `NODE_EXTRA_CA_CERTS` to its certificate and keep TLS verification enabled.

## Evidence and limits

Verification passes: **27 live HTTP checks, 26 Java offline checks, 24 Node tests, and 4 Terraform tests**. A Terraform plan after apply reports no changes. See [verification notes](docs/verification.md).

Live client authentication, processor validation, managed signing-key retrieval and JWKS publication are exercised. **Real OIDC login and downstream redemption are not.** This is a deliberately narrow, single-tenant, one-client/one-destination proof. Production use requires real identity resolution/entitlements and downstream profile/client/replay enforcement.

The plugin is deployed in `pingfederate-xaa`. The existing base Docker files were preserved; an optional `docker-compose.xaa.yml` provides a reproducible JAR mount. Terraform state and local fixture files contain secrets and are ignored by Git. Do not commit them.
