package twistlock

import (
	"github.com/circleci/terraform-provider-twistlock/model"
	"github.com/hashicorp/terraform/helper/schema"

	"github.com/circleci/terraform-provider-twistlock/client"
)

func resourceUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceUserCreate,
		Read:   resourceUserRead,
		Update: resourceUserUpdate,
		Delete: resourceUserDelete,
		Exists: resourceUserExists,

		Schema: map[string]*schema.Schema{
			"username":  {Type: schema.TypeString, Required: true},
			"password":  {Type: schema.TypeString, Required: true},
			"role":      {Type: schema.TypeString, Required: true},
			"auth_type": {Type: schema.TypeString, Required: true},
		},
	}
}

func userFromResource(d *schema.ResourceData) *model.User {
	var role model.UserRole
	var auth model.UserAuthType

	role.UnmarshalText([]byte(d.Get("role").(string)))
	auth.UnmarshalText([]byte(d.Get("auth_type").(string)))

	return &model.User{
		Username: d.Get("username").(string),
		Password: d.Get("password").(string),
		Role:     role,
		AuthType: auth,
	}
}

func resourceUserCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)
	u, err := client.CreateUser(userFromResource(d))

	if err != nil {
		return err
	}

	d.SetId(u.ID)
	return nil
}

func resourceUserRead(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)
	u, found, err := client.ReadUser(d.Id())

	if err != nil {
		return err
	}
	if !found {
		// Tell terraform the user has been deleted
		d.SetId("")
		return nil
	}

	roleText, err := u.Role.MarshalText()
	if err != nil {
		return err
	}
	authTypeText, err := u.AuthType.MarshalText()
	if err != nil {
		return err
	}

	d.Set("username", u.Username)
	d.Set("role", string(roleText))
	d.Set("auth_type", string(authTypeText))

	return nil
}

func resourceUserUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceUserCreate(d, m)
}

func resourceUserDelete(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)
	err := client.DeleteUser(userFromResource(d))

	if err != nil {
		return err
	}

	// Setting a blank ID is not strictly necessary, including for completeness
	d.SetId("")
	return nil
}

func resourceUserExists(d *schema.ResourceData, m interface{}) (bool, error) {
	client := m.(client.Client)

	_, found, err := client.ReadUser(d.Id())
	return found, err
}
