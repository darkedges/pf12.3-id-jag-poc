terraform {
  required_version = ">= 1.10, < 2.0"
  required_providers {
    pingfederate = {
      source  = "pingidentity/pingfederate"
      version = "1.9.0"
    }
    restapi = {
      source  = "Mastercard/restapi"
      version = "3.0.0"
    }
  }
}

provider "pingfederate" {
  https_host               = var.admin_url
  product_version          = "12.3"
  username                 = var.admin_username
  password                 = var.admin_password
  insecure_trust_all_tls   = var.local_test_insecure_tls
  ca_certificate_pem_files = var.ca_certificate_file == null ? null : [var.ca_certificate_file]
}

# The pinned Ping provider does not implement token-generator instances or
# generator groups, despite referring to them in some examples. Use real CRUD
# resources for those endpoints so they participate in refresh/plan/import.
provider "restapi" {
  uri                  = "${var.admin_url}/pf-admin-api/v1"
  username             = var.admin_username
  password             = var.admin_password
  insecure             = var.local_test_insecure_tls
  root_ca_file         = var.ca_certificate_file
  write_returns_object = true
  debug                = false
  timeout              = 30
  headers = {
    "X-XSRF-Header" = "PingFederate"
    "Content-Type"  = "application/json"
  }
}
