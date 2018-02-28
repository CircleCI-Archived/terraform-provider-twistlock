package twistlock

import (
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
			"username": {Type: schema.TypeString, Required: true},
			"password": {Type: schema.TypeString, Required: true},
			"base_url": {Type: schema.TypeString, Required: true},
		},
		ResourcesMap: map[string]*schema.Resource{
			"twistlock_user": resourceUser(),
		},
		ConfigureFunc: configureProvider,
	}
}
