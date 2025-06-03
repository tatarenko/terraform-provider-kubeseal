resource "kubeseal_raw" "example" {
  name      = "example"
  namespace = "default"
  secret    = "very_secret_secret"
  scope     = 0
  pubkey    = <<-EOT
  XXXXXXXXXXXXXXXXXXXXXXXXXX
  XXXXXXXXXXXXXXXXXXXXXXXXXX
  -----END CERTIFICATE-----
  EOT
}

