// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

var (
	_ provider.Provider = &terraformKubeseal{}
)

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &terraformKubeseal{
			version: version,
		}
	}
}

type terraformKubeseal struct {
	version string
}

func (p *terraformKubeseal) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "kubeseal"
	resp.Version = p.version
}

// Schema defines the provider-level schema for configuration data.
func (p *terraformKubeseal) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
}

func (p *terraformKubeseal) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
}

func (p *terraformKubeseal) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		//		NewCoffeesDataSource,
	}
}

func (p *terraformKubeseal) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewRawResource,
	}
}
