package twistlock

import (
	"github.com/hashicorp/terraform/helper/schema"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/circleci/terraform-provider-twistlock/model"
)

func resourceMachineUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceMachineUserCreate,
		Read:   resourceUserRead,
		Update: resourceMachineUserUpdate,
		Delete: resourceUserDelete,
		Exists: resourceUserExists,

		Schema: map[string]*schema.Schema{
			"username":  {Type: schema.TypeString, Required: true},
			"password":  {Type: schema.TypeString, Required: true, Sensitive: true},
			"role":      {Type: schema.TypeString, Required: true},
			"auth_type": {Type: schema.TypeString, Required: true},
		},
	}
}

func resourceMachineUserCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)

	u := userFromResource(d)
	u.Password = d.Get("password").(string)
	user, err := client.CreateUser(u)

	if err != nil {
		return err
	}

	d.SetId(user.ID)
	return nil
}

func resourceMachineUserUpdate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)
	needsUpdate := false
	var userUpdate model.User

	if d.HasChange("role") {
		needsUpdate = true
		role := d.Get("role").(string)
		userUpdate.Role.UnmarshalText([]byte(role))
	}
	if d.HasChange("auth_type") {
		needsUpdate = true
		authType := d.Get("auth_type").(string)
		userUpdate.AuthType.UnmarshalText([]byte(authType))
	}
	if d.HasChange("password") {
		needsUpdate = true
		userUpdate.Password = d.Get("password").(string)
	}

	if needsUpdate {
		_, err := client.UpdateUser(&userUpdate)
		if err != nil {
			return err
		}
	}

	return resourceUserRead(d, m)
}
