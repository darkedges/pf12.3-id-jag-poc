mock_provider "pingfederate" {}
mock_provider "restapi" {}

variables {
  admin_password           = "mock-only"
  requesting_client_secret = "mock-requesting-client-secret-32-characters"
  audience_client_secret   = "mock-audience-client-secret-32-characters"
  subject_issuer           = "https://subject.example.test"
  # Schema fixture only; no cryptographic verification is claimed by these tests.
  subject_jwks            = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"mock\",\"e\":\"AQAB\",\"n\":\"mock\"}]}"
  authorized_test_subject = "authorized-user"
}

run "restricted_configuration" {
  command = plan
  assert {
    condition     = pingfederate_oauth_client.requesting.grant_types == toset(["TOKEN_EXCHANGE"])
    error_message = "The requesting client must be token-exchange-only."
  }
  assert {
    condition     = !pingfederate_oauth_client.audience.enabled
    error_message = "The routing-only client must remain disabled."
  }
  assert {
    condition     = pingfederate_oauth_client.requesting.restrict_scopes && pingfederate_oauth_client.requesting.restricted_scopes == toset(["read:reports"])
    error_message = "The requesting client must be scope-restricted."
  }
  assert {
    condition     = pingfederate_oauth_token_exchange_token_generator_mapping.xaa.attribute_contract_fulfillment.http_request.source.type == "CONTEXT"
    error_message = "Use PF's trusted HTTP request context, not a request-supplied identity or expression."
  }
  assert {
    condition     = length(pingfederate_oauth_token_exchange_processor_policy.xaa.processor_mappings[0].issuance_criteria.conditional_criteria) == 2
    error_message = "Subject authorization and authorized-party binding must both be present."
  }
}

run "reject_remote_tls_bypass" {
  command = plan
  variables {
    admin_url               = "https://pf.example.test:9999"
    local_test_insecure_tls = true
  }
  expect_failures = [var.local_test_insecure_tls]
}

run "reject_private_jwks" {
  command = plan
  variables {
    subject_jwks = "{\"keys\":[{\"kty\":\"RSA\",\"d\":\"private\"}]}"
  }
  expect_failures = [var.subject_jwks]
}

run "reject_shared_client_secret" {
  command = plan
  variables {
    audience_client_secret = "mock-requesting-client-secret-32-characters"
  }
  expect_failures = [var.audience_client_secret]
}
