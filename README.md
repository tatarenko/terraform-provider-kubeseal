terraform-kubeseal
================================

A very barebones provider that exposes basic `kubeseal` functionality as a terraform data source.

### Usage


```HCL
terraform {
  required_providers {
    kubeseal = {
      source = "XXXXXX"
      version = "0.1.0"
    }
  }
}

provider "kubeseal" {
}


```
