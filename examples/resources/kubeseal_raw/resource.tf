resource "kubeseal_raw" "exanple" {
  name      = "example"
  namespace = "default"
  secret    = "very_secret_secret"
  scope     = 1
  pubkey    = <<-EOT
  XXXXXXXXXXXXXXXXXXXXXXXXXX
  XXXXXXXXXXXXXXXXXXXXXXXXXX
  -----END CERTIFICATE-----
  EOT
}
