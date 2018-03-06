package twistlock

import (
	"github.com/hashicorp/terraform/helper/encryption"
	"github.com/hashicorp/terraform/helper/schema"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/circleci/terraform-provider-twistlock/model"
	"github.com/circleci/terraform-provider-twistlock/password"
)

func resourceUser() *schema.Resource {
	return &schema.Resource{
		Create: resourceUserCreate,
		Read:   resourceUserRead,
		Update: resourceUserUpdate,
		Delete: resourceUserDelete,
		Exists: resourceUserExists,

		Schema: map[string]*schema.Schema{
			"username":           {Type: schema.TypeString, Required: true},
			"pgp_key":            {Type: schema.TypeString, Required: true},
			"role":               {Type: schema.TypeString, Required: true},
			"auth_type":          {Type: schema.TypeString, Required: true},
			"encrypted_password": {Type: schema.TypeString, Computed: true},
			"key_fingerprint":    {Type: schema.TypeString, Computed: true},
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
		Role:     role,
		AuthType: auth,
	}
}

func resourceUserCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)

	encryptionKey, err := encryption.RetrieveGPGKey(d.Get("pgp_key").(string))
	if err != nil {
		return err
	}

	password, err := password.RandomString(30)
	if err != nil {
		return err
	}

	fingerprint, encrypted, err := encryption.EncryptValue(encryptionKey, password, "Generated Password")
	if err != nil {
		return err
	}

	u := userFromResource(d)
	u.Password = password
	user, err := client.CreateUser(u)

	if err != nil {
		return err
	}

	d.SetId(user.ID)
	d.Set("encrypted_password", encrypted)
	d.Set("key_fingerprint", fingerprint)
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

	d.Set("username", u.Username)
	d.Set("role", string(u.Role))
	d.Set("auth_type", string(u.AuthType))

	return nil
}

func resourceUserUpdate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)
	needsUpdate := false
	userUpdate := userFromResource(d)
	// Prevent accidental password changes by ensuring this field is blank
	userUpdate.Password = ""

	if d.HasChange("role") {
		needsUpdate = true
	}
	if d.HasChange("auth_type") {
		needsUpdate = true
	}

	if needsUpdate {
		_, err := client.UpdateUser(userUpdate)
		if err != nil {
			return err
		}
	}

	return resourceUserRead(d, m)
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
