package provider

import (
	"bytes"
	"context"
	ssv1alpha1 "github.com/bitnami-labs/sealed-secrets/pkg/apis/sealedsecrets/v1alpha1"
	"github.com/bitnami-labs/sealed-secrets/pkg/kubeseal"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
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
				Description: "Name of the secret",
				Required:    true,
			},
			"namespace": schema.StringAttribute{
				Description: "Namespace of the secret",
				Required:    true,
			},
			"secret": schema.StringAttribute{
				Description: "Plain text secret to be encrypted",
				Required:    true,
				Sensitive:   true,
			},
			"scope": schema.Int32Attribute{
				Description: "Sealed secret scope: 0 strict | 1 namespace-wide | 2 cluster-wide",
				Required:    true,
				Validators: []validator.Int32{
					int32validator.Between(0, 2),
				},
				MarkdownDescription: `
				0 strict: the secret must be sealed with exactly the same name and namespace.
				1 namespace-wide: you can freely rename the sealed secret within a given namespace.
				2 cluster-wide: the secret can be unsealed in any namespace and can be given any name.
				[Official Docs](https://github.com/bitnami-labs/sealed-secrets/tree/main?tab=readme-ov-file#scopes)
				`,
			},
			"pubkey": schema.StringAttribute{
				Required:    true,
				Description: "Public Key to encrypt secret with",
			},
			"sealed": schema.StringAttribute{
				Computed:    true,
				Description: "Encrypted secret string",
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of last updated time",
			},
		},
	}
}

func encryptWrapper(plan rawSealModel, diagnostics diag.Diagnostics) (rawSealModel, error) {
	reader := strings.NewReader(plan.PubKey.ValueString())
	pubKey, err := kubeseal.ParseKey(reader)
	if err != nil {
		diagnostics.AddError("Error parsing pubkey", "Unexpected error: "+err.Error())
		return plan, err
	}

	w := new(bytes.Buffer)
	sealingScope := ssv1alpha1.SealingScope(plan.Scope.ValueInt32())

	err = kubeseal.EncryptSecretItem(w, plan.Name.ValueString(), plan.Namespace.ValueString(), []byte(plan.Secret.ValueString()), sealingScope, pubKey)
	if err != nil {
		diagnostics.AddError("Error encrypting secret item", "Unexpected error: "+err.Error())
		return plan, err
	}

	plan.Sealed = types.StringValue(w.String())
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	return plan, nil
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

	var err error
	plan, err = encryptWrapper(plan, resp.Diagnostics)
	if err != nil {
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *rawResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan
	var plan rawSealModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var err error
	plan, err = encryptWrapper(plan, resp.Diagnostics)
	if err != nil {
		return
	}

	// Set state to fully populated data
	diags = resp.State.Set(ctx, plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *rawResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
}

func (r *rawResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
}
