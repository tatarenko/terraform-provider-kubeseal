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
	_ resource.Resource = &rawsResource{}
)

func NewRawsResource() resource.Resource {
	return &rawsResource{}
}

// rawsResource is the resource implementation.
type rawsResource struct {
}

type rawsSealModel struct {
	Name        types.String `tfsdk:"name"`
	Namespace   types.String `tfsdk:"namespace"`
	Values      types.Map    `tfsdk:"values"`
	Scope       types.Int32  `tfsdk:"scope"`
	PubKey      types.String `tfsdk:"pubkey"`
	Sealed      types.Map    `tfsdk:"sealed"`
	LastUpdated types.String `tfsdk:"last_updated"`
}

// Metadata returns the resource type name.
func (r *rawsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_raws"
}

// Schema defines the schema for the resource.
func (r *rawsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages multiple sealed secrets in a single resource.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Description: "Name of the secret",
				Required:    true,
			},
			"namespace": schema.StringAttribute{
				Description: "Namespace of the secret",
				Required:    true,
			},
			"values": schema.MapAttribute{
				Description: "Map of secret key-value pairs to be encrypted",
				Required:    true,
				Sensitive:   true,
				ElementType: types.StringType,
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
				Description: "Public Key to encrypt secrets with",
			},
			"sealed": schema.MapAttribute{
				Computed:    true,
				Description: "Map of encrypted secret values",
				ElementType: types.StringType,
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of last updated time",
			},
		},
	}
}

func encryptMapWrapper(plan rawsSealModel, diagnostics diag.Diagnostics) (rawsSealModel, error) {
	reader := strings.NewReader(plan.PubKey.ValueString())
	pubKey, err := kubeseal.ParseKey(reader)
	if err != nil {
		diagnostics.AddError("Error parsing pubkey", "Unexpected error: "+err.Error())
		return plan, err
	}

	sealingScope := ssv1alpha1.SealingScope(plan.Scope.ValueInt32())

	// Extract the values map
	values := make(map[string]string)
	diags := plan.Values.ElementsAs(context.Background(), &values, false)
	if diags.HasError() {
		diagnostics.Append(diags...)
		return plan, err
	}

	// Encrypt each value in the map
	sealedValues := make(map[string]string)
	for key, value := range values {
		w := new(bytes.Buffer)
		err = kubeseal.EncryptSecretItem(w, plan.Name.ValueString(), plan.Namespace.ValueString(), []byte(value), sealingScope, pubKey)
		if err != nil {
			diagnostics.AddError("Error encrypting secret item", "Unexpected error for key '"+key+"': "+err.Error())
			return plan, err
		}
		sealedValues[key] = w.String()
	}

	// Convert the sealed values map to types.Map
	sealedMap, diags := types.MapValueFrom(context.Background(), types.StringType, sealedValues)
	if diags.HasError() {
		diagnostics.Append(diags...)
		return plan, err
	}

	plan.Sealed = sealedMap
	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))
	return plan, nil
}

// Create a new resource.
func (r *rawsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	// Retrieve values from plan
	var plan rawsSealModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var err error
	plan, err = encryptMapWrapper(plan, resp.Diagnostics)
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

func (r *rawsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	// Retrieve values from plan
	var plan rawsSealModel
	diags := req.Plan.Get(ctx, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	var err error
	plan, err = encryptMapWrapper(plan, resp.Diagnostics)
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

func (r *rawsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	// No-op for now
}

func (r *rawsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	// No-op for now
}
