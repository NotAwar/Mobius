package provider

import (
	"context"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-log/tflog"
	"os"
	"terraform-provider-mobiusmdm/mobiusdm_client"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// This Terraform provider is based on the example provider from the Terraform
// documentation. It is a simple provider that interacts with the MobiusDM API.

// Ensure MobiusDMProvider satisfies various provider interfaces.
var _ provider.Provider = &MobiusDMProvider{}
var _ provider.ProviderWithFunctions = &MobiusDMProvider{}

// MobiusDMProvider defines the provider implementation.
type MobiusDMProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// MobiusDMProviderModel describes the provider data model. It requires a URL
// and api key to communicate with MobiusDM.
type MobiusDMProviderModel struct {
	Url    types.String `tfsdk:"url"`
	ApiKey types.String `tfsdk:"apikey"`
}

func (p *MobiusDMProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "mobiusmdm"
	resp.Version = p.version
}

func (p *MobiusDMProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Attributes: map[string]schema.Attribute{
			"url": schema.StringAttribute{
				MarkdownDescription: "URL of your MobiusDM server",
				Optional:            true,
			},
			"apikey": schema.StringAttribute{
				MarkdownDescription: "API Key for authentication",
				Optional:            true,
				Sensitive:           true,
			},
		},
	}
}

func (p *MobiusDMProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config MobiusDMProviderModel

	tflog.Info(ctx, "Configuring MobiusDM client")

	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	if config.Url.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			"Unknown MobiusDM url",
			"Url is unknown")
	}

	if config.ApiKey.IsUnknown() {
		resp.Diagnostics.AddAttributeError(
			path.Root("apikey"),
			"Unknown MobiusDM apikey",
			"api key is unknown")
	}

	if resp.Diagnostics.HasError() {
		return
	}

	url := os.Getenv("MOBIUSDAEMONM_URL")
	apikey := os.Getenv("MOBIUSDAEMONM_APIKEY")

	if !config.Url.IsNull() {
		url = config.Url.ValueString()
	}

	if !config.ApiKey.IsNull() {
		apikey = config.ApiKey.ValueString()
	}

	if url == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("url"),
			"Missing url",
			"Really, the url is required")
	}

	if apikey == "" {
		resp.Diagnostics.AddAttributeError(
			path.Root("apikey"),
			"Missing apikey",
			"Really, the apikey is required")
	}

	if resp.Diagnostics.HasError() {
		return
	}

	// Example client configuration for data sources and resources
	client := mobiusdm_client.NewMobiusDMClient(url, apikey)
	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *MobiusDMProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTeamsResource,
	}
}

func (p *MobiusDMProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *MobiusDMProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &MobiusDMProvider{
			version: version,
		}
	}
}
