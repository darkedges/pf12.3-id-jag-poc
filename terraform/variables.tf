variable "admin_url" {
  type    = string
  default = "https://localhost:9999"
  validation {
    condition     = can(regex("^https://[^/?#]+$", var.admin_url))
    error_message = "Use an HTTPS admin origin without a trailing slash."
  }
}

variable "admin_username" {
  type    = string
  default = "administrator"
}

variable "admin_password" {
  type      = string
  sensitive = true
  ephemeral = true
}

variable "local_test_insecure_tls" {
  type    = bool
  default = false
  validation {
    condition     = !var.local_test_insecure_tls || can(regex("^https://(localhost|127\\.0\\.0\\.1)(:[0-9]+)?$", var.admin_url))
    error_message = "TLS bypass is allowed only for the local test server. Use a trusted certificate elsewhere."
  }
}

variable "ca_certificate_file" {
  type    = string
  default = null
}

variable "pf_issuer" {
  type    = string
  default = "https://localhost:9031"
}

variable "requesting_client_id" {
  type    = string
  default = "xaa-primary-client"
}

variable "requesting_client_secret" {
  type      = string
  sensitive = true
  validation {
    condition     = length(var.requesting_client_secret) >= 32
    error_message = "Provide a randomly generated client secret of at least 32 characters."
  }
}

variable "subject_issuer" {
  type        = string
  description = "Exact trusted ID-token issuer; use a separate fixture issuer only in the local proof."
}

variable "audience_client_secret" {
  type        = string
  sensitive   = true
  description = "Independent random secret for the disabled routing-only registration. Never used for token requests."
  validation {
    condition     = length(var.audience_client_secret) >= 32 && var.audience_client_secret != var.requesting_client_secret
    error_message = "Supply a separate random secret of at least 32 characters."
  }
}

variable "subject_jwks" {
  type        = string
  description = "Public-only JWKS for the trusted subject issuer. Private keys must never be supplied."
  validation {
    condition = can(jsondecode(var.subject_jwks).keys) && try(length(jsondecode(var.subject_jwks).keys) > 0 && alltrue([
      for key in jsondecode(var.subject_jwks).keys : key.kty == "RSA" && length(key.n) > 0 && length(key.e) > 0 && length(key.kid) > 0 && length(setintersection(toset(keys(key)), toset(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]))) == 0
    ]), false)
    error_message = "Supply a nonempty RSA public JWKS without private key parameters."
  }
}

variable "authorized_test_subject" {
  type        = string
  description = "The sole subject authorized by this narrow test policy. Replace the policy with real entitlements before production."
}

variable "target_issuer" {
  type    = string
  default = "https://target.example.test"
}

variable "target_client_id" {
  type    = string
  default = "target-client"
}

variable "target_resource" {
  type    = string
  default = "https://api.example.test/reports"
}

variable "allowed_scopes" {
  type    = set(string)
  default = ["read:reports"]
  validation {
    condition     = length(var.allowed_scopes) > 0 && !contains(var.allowed_scopes, "openid")
    error_message = "Provide at least one API scope; openid is outside this proof."
  }
}
