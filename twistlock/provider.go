package twistlock

import (
	"os"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/hashicorp/terraform/helper/schema"
)

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	return client.NewClient(d.Get("username").(string),
		d.Get("password").(string),
		d.Get("base_url").(string)), nil
}

func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"username": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("TWISTLOCK_USERNAME", os.Getenv("TWISTLOCK_USERNAME"))},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("TWISTLOCK_PASSWORD", os.Getenv("TWISTLOCK_PASSWORD"))},
			"base_url": {
				Type:        schema.TypeString,
				Required:    true,
				DefaultFunc: schema.EnvDefaultFunc("TWISTLOCK_BASE_URL", os.Getenv("TWISTLOCK_BASE_URL"))},
		},
		ResourcesMap: map[string]*schema.Resource{
			"twistlock_user": resourceUser(),
		},
		ConfigureFunc: configureProvider,
	}
}
