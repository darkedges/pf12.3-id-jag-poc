output "token_endpoint" {
  value = "${var.pf_issuer}/as/token.oauth2"
}
output "jwks_uri" {
  value = "${var.pf_issuer}/pf/JWKS"
}
output "requesting_client_id" {
  value = pingfederate_oauth_client.requesting.client_id
}
output "generator_id" {
  value = restapi_object.generator.id
}
