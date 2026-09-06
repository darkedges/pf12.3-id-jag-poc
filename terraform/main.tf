locals {
  scope_string = join(" ", sort(tolist(var.allowed_scopes)))
  generator_contract = [
    "approved_scope", "authenticated_client_id", "http_request", "sub", "subject_client_id", "subject_exp"
  ]
  generator_fields = {
    "Issuer"               = var.pf_issuer
    "Requesting Client ID" = var.requesting_client_id
    "Target Issuer"        = var.target_issuer
    "Target Client ID"     = var.target_client_id
    "Resource"             = var.target_resource
    "Allowed Scopes"       = local.scope_string
    "Lifetime Seconds"     = "300"
  }
}

# Manage only our scope entries, not the entire singleton auth-server settings.
resource "restapi_object" "scope" {
  for_each                = var.allowed_scopes
  path                    = "/oauth/authServerSettings/scopes/commonScopes"
  id_attribute            = "name"
  ignore_server_additions = true
  data = jsonencode({
    name        = each.value
    description = "XAA proof: ${each.value}"
    dynamic     = false
  })
}

resource "restapi_object" "generator" {
  path                    = "/sp/tokenGenerators"
  ignore_server_additions = true
  data = jsonencode({
    id                  = "xaaIdJag"
    name                = "XAA ID-JAG 12.3.3 proof"
    pluginDescriptorRef = { id = "com.darkedges.pingfederate.xaa.IdJagTokenGenerator" }
    configuration = {
      fields = [for name in sort(keys(local.generator_fields)) : { name = name, value = local.generator_fields[name] }]
      tables = []
    }
    attributeContract = {
      coreAttributes     = [for name in local.generator_contract : { name = name }]
      extendedAttributes = []
    }
  })
}

resource "pingfederate_idp_token_processor" "subject" {
  processor_id          = "xaaSubjectJwt"
  name                  = "XAA trusted subject JWT"
  plugin_descriptor_ref = { id = "com.pingidentity.pf.tokenprocessors.jwt.JwtTokenProcessor" }
  attribute_contract = {
    core_attributes     = [{ name = "sub", masked = true }]
    extended_attributes = [for name in ["aud", "azp", "exp"] : { name = name, masked = true }]
    mask_ognl_values    = true
  }
  configuration = {
    fields = [
      { name = "Require Audience", value = "true" },
      { name = "Require Expiration Time", value = "true" },
      { name = "Require Issued At Time", value = "true" },
      { name = "Require Not Before Time", value = "false" },
      { name = "Default Cache Duration", value = "720" },
      { name = "Allowed Clock Skew", value = "0" },
      { name = "Max Future Validity", value = "10" }
    ]
    tables = [
      {
        name = "Allowed Issuers"
        rows = [{ fields = [
          { name = "Issuer", value = var.subject_issuer },
          { name = "JWKS", value = var.subject_jwks }
        ] }]
      },
      {
        name = "Allowed Audiences"
        rows = [{ fields = [{ name = "Audience", value = var.requesting_client_id }] }]
      }
    ]
  }
}

resource "pingfederate_oauth_token_exchange_processor_policy" "xaa" {
  policy_id            = "xaaPolicy"
  name                 = "XAA authorized test subject"
  actor_token_required = false
  attribute_contract = {
    extended_attributes = [for name in ["subject_client_id", "subject_exp", "approved_scope"] : { name = name }]
  }
  processor_mappings = [{
    subject_token_type      = "urn:ietf:params:oauth:token-type:id_token"
    subject_token_processor = { id = pingfederate_idp_token_processor.subject.processor_id }
    attribute_contract_fulfillment = {
      subject           = { source = { type = "SUBJECT_TOKEN" }, value = "sub" }
      subject_client_id = { source = { type = "SUBJECT_TOKEN" }, value = "aud" }
      subject_exp       = { source = { type = "SUBJECT_TOKEN" }, value = "exp" }
      approved_scope    = { source = { type = "TEXT" }, value = local.scope_string }
    }
    issuance_criteria = {
      conditional_criteria = [
        {
          source         = { type = "SUBJECT_TOKEN" }
          attribute_name = "sub"
          condition      = "EQUALS"
          value          = var.authorized_test_subject
          error_result   = "Subject is not authorized for the XAA proof"
        },
        {
          source         = { type = "SUBJECT_TOKEN" }
          attribute_name = "azp"
          condition      = "EQUALS"
          value          = var.requesting_client_id
          error_result   = "Subject client binding rejected"
        }
      ]
    }
  }]
}

resource "pingfederate_oauth_client" "requesting" {
  client_id   = var.requesting_client_id
  name        = "XAA token exchange proof client"
  enabled     = true
  grant_types = ["TOKEN_EXCHANGE"]
  client_auth = { type = "SECRET", secret = var.requesting_client_secret }
  token_exchange_processor_policy_ref = {
    id = pingfederate_oauth_token_exchange_processor_policy.xaa.policy_id
  }
  restrict_scopes   = true
  restricted_scopes = var.allowed_scopes
  depends_on        = [restapi_object.scope]
}

# This registration never authenticates. It exists solely for PF 12.3.3's
# audience lookup. The native provider requires at least one grant, so keep this
# validation-only registration disabled with its own unused random secret.
resource "pingfederate_oauth_client" "audience" {
  client_id   = var.target_issuer
  name        = "XAA target issuer routing only"
  enabled     = false
  grant_types = ["ACCESS_TOKEN_VALIDATION"]
  client_auth = { type = "SECRET", secret = var.audience_client_secret }
}

resource "restapi_object" "generator_group" {
  path                    = "/oauth/tokenExchange/generator/groups"
  ignore_server_additions = true
  data = jsonencode({
    id           = "xaaGroup"
    name         = "XAA explicit resource routing"
    resourceUris = [var.target_resource]
    generatorMappings = [{
      requestedTokenType = "urn:ietf:params:oauth:token-type:id-jag"
      tokenGenerator     = { id = restapi_object.generator.id }
      defaultMapping     = true
    }]
  })
}

resource "pingfederate_oauth_token_exchange_token_generator_mapping" "xaa" {
  source_id = pingfederate_oauth_token_exchange_processor_policy.xaa.policy_id
  target_id = restapi_object.generator.id
  attribute_contract_fulfillment = {
    sub                     = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject" }
    subject_client_id       = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject_client_id" }
    subject_exp             = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "subject_exp" }
    approved_scope          = { source = { type = "TOKEN_EXCHANGE_PROCESSOR_POLICY" }, value = "approved_scope" }
    authenticated_client_id = { source = { type = "CONTEXT" }, value = "ClientId" }
    http_request            = { source = { type = "CONTEXT" }, value = "HttpRequest" }
  }
}
