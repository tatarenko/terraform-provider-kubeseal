// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package provider

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealed-secrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/crypto"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"io"
	"k8s.io/client-go/util/cert"
	"strings"
	"time"
)

// Ensure the implementation satisfies the expected interfaces.
var (
	_ resource.Resource = &rawResource{}
)

func NewRawResource() resource.Resource {
	return &rawResource{}
}

// rawResource is the resource implementation.
type rawResource struct {
}

type rawSealModel struct {
	Name        types.String `tfsdk:"name"`
	Namespace   types.String `tfsdk:"namespace"`
	Secret      types.String `tfsdk:"secret"`
	Scope       types.Int32  `tfsdk:"scope"`
	PubKey      types.String `tfsdk:"pubkey"`
	Sealed      types.String `tfsdk:"sealed"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

// Metadata returns the resource type name.
func (r *rawResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_raw"
}

// Schema defines the schema for the resource.
func (r *rawResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages an order.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the Secret",
				Required:    true,
			},
			"namespace": schema.StringAttribute{
				Required: true,
			},
			"secret": schema.StringAttribute{
				Required:  true,
				Sensitive: true,
			},
			"scope": schema.Int32Attribute{
				Required: true,
			},
			"pubkey": schema.StringAttribute{
				Required: true,
			},
			"sealed": schema.StringAttribute{
				Computed: true,
			},
			"last_updated": schema.StringAttribute{
				Computed: true,
			},
		},
	}
}

// Configure adds the provider configured client to the resource.
func (r *rawResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
}

func ParseKey(r io.Reader) (*rsa.PublicKey, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	certs, err := cert.ParseCertsPEM(data)
	if err != nil {
		return nil, err
	}

	// ParseCertsPem returns error if len(certs) == 0, but best to be sure...
	if len(certs) == 0 {
		return nil, errors.New("failed to read any certificates")
	}

	cert, ok := certs[0].PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("expected RSA public key but found %v", certs[0].PublicKey)
	}

	if time.Now().After(certs[0].NotAfter) {
		return nil, fmt.Errorf("failed to encrypt using an expired certificate on %v", certs[0].NotAfter.Format("January 2, 2006"))
	}

	return cert, nil
}

// Create a new resource.
func (r *rawResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan rawSealModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	reader := strings.NewReader(plan.PubKey.ValueString())

	spkiKey, err := ParseKey(reader)
	if err != nil {
		resp.Diagnostics.AddError("Error parsing pubkey", "Unexpected error: "+err.Error())
		return
	}

	label := ssv1alpha1.EncryptionLabel(plan.Namespace.ValueString(), plan.Name.ValueString(), ssv1alpha1.SealingScope(plan.Scope.ValueInt32()))
	out, err := crypto.HybridEncrypt(rand.Reader, spkiKey, []byte(plan.Secret.ValueString()), label)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error encrypting value",
			"Unexpected error: "+err.Error(),
		)
		return
	}

	sealed := base64.StdEncoding.EncodeToString(out)
	if len(sealed) == 0 {
		resp.Diagnostics.AddError(
			"Error Sealing not successful", "")
		return
	}

	plan.Sealed = types.StringValue(base64.StdEncoding.EncodeToString(out))
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *rawResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

func (r *rawResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan
	var plan rawSealModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	reader := strings.NewReader(plan.PubKey.ValueString())

	spkiKey, err := ParseKey(reader)
	if err != nil {
		resp.Diagnostics.AddError("Error parsing pubkey", "Unexpected error: "+err.Error())
		return
	}

	label := ssv1alpha1.EncryptionLabel(plan.Namespace.ValueString(), plan.Name.ValueString(), ssv1alpha1.SealingScope(plan.Scope.ValueInt32()))
	out, err := crypto.HybridEncrypt(rand.Reader, spkiKey, []byte(plan.Secret.ValueString()), label)
	if err != nil {
		resp.Diagnostics.AddError(
			"Error encrypting value",
			"Unexpected error: "+err.Error(),
		)
		return
	}

	sealed := base64.StdEncoding.EncodeToString(out)
	if len(sealed) == 0 {
		resp.Diagnostics.AddError(
			"Error Sealing not successful", "")
		return
	}

	plan.Sealed = types.StringValue(sealed)
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *rawResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}
