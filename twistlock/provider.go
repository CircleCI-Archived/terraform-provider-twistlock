package twistlock

import (
	"os"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/hashicorp/terraform/helper/schema"
)

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	return client.NewClient(d.Get("username").(string),
		d.Get("password").(string),
		d.Get("base_url").(string),
		d.Get("tls_skip_verify").(bool)), nil
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("TWISTLOCK_USERNAME", os.Getenv("TWISTLOCK_USERNAME")),
				Description: "Username to log in with",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("TWISTLOCK_PASSWORD", os.Getenv("TWISTLOCK_PASSWORD")),
				Description: "Password to log in with",
			},
			"base_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("TWISTLOCK_BASE_URL", os.Getenv("TWISTLOCK_BASE_URL")),
				Description: "Base URL for the Twistlock API, e.g. http://localhost:8081/api/v1",
			},
			"tls_skip_verify": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     false,
				Description: "Trust self-signed certificates presented by the Twistlock Console",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"twistlock_user":         resourceUser(),
			"twistlock_machine_user": resourceMachineUser(),
			"twistlock_cve_policy":   resourceCVEPolicy(),
		},
		ConfigureFunc: configureProvider,
	}
}
