package twistlock

import (
	"fmt"
	"io/ioutil"
	"regexp"
	"testing"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/circleci/terraform-provider-twistlock/model"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
	"github.com/hashicorp/vault/helper/pgpkeys"
)

const terraformTestPublicKeyPath string = "testdata/test-gpg-keys/terraform.pub"

// Content of testdata/test-gpg-keys/terraform.pub
var terraformTestPublicKey string

const terraformTestPrivateKeyPath string = "testdata/test-gpg-keys/terraform.priv"

// Content of testdata/test-gpg-keys/terraform.priv
// There is no associated passphrase
var terraformTestPrivateKey string

func init() {
	publicKeyBytes, err := ioutil.ReadFile(terraformTestPublicKeyPath)
	if err != nil {
		panic(fmt.Sprintf("Could not read test public key for: %s", err))
	}

	terraformTestPublicKey = string(publicKeyBytes)

	privateKeyBytes, err := ioutil.ReadFile(terraformTestPrivateKeyPath)
	if err != nil {
		panic(fmt.Sprintf("Could not read test private key for: %s", err))
	}

	terraformTestPrivateKey = string(privateKeyBytes)
}

func TestAccUser(t *testing.T) {
	username := acctest.RandString(8)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		CheckDestroy: testAccUserDestroy,
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccUser_BasicConfig(username, "testdata/test-gpg-keys/terraform.pub", model.RoleUser, model.AuthTypeBasic),
				Check: resource.ComposeTestCheckFunc(
					CheckTerraformState("twistlock_user.test_user", AttrMap{
						"username":  AttrLeaf(username),
						"pgp_key":   AttrLeaf(terraformTestPublicKey),
						"role":      AttrLeaf(model.RoleUser),
						"auth_type": AttrLeaf(model.AuthTypeBasic),
					}),
					testAccUser_GeneratedPassword,
				),
			},
			// Update role
			resource.TestStep{
				Config: testAccUser_BasicConfig(username, "testdata/test-gpg-keys/terraform.pub", model.RoleDefenderManager, model.AuthTypeBasic),
				Check: resource.ComposeTestCheckFunc(
					CheckTerraformState("twistlock_user.test_user", AttrMap{
						"username":  AttrLeaf(username),
						"pgp_key":   AttrLeaf(terraformTestPublicKey),
						"role":      AttrLeaf(model.RoleDefenderManager),
						"auth_type": AttrLeaf(model.AuthTypeBasic),
					}),
					testAccUser_GeneratedPassword,
				),
			},
		},
	})
}

func TestAccUser_CannotMutateImmutableUserProperties(t *testing.T) {
	username := acctest.RandString(8)

	immutableUsernameError, err := regexp.Compile("Twistlock usernames are immutable")
	if err != nil {
		t.Fatalf("Could not compile username check regular expression")
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		CheckDestroy: testAccUserDestroy,
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccUser_BasicConfig(username, "testdata/test-gpg-keys/terraform.pub", model.RoleUser, model.AuthTypeBasic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("twistlock_user.test_user", "username", username),
					resource.TestCheckResourceAttr("twistlock_user.test_user", "pgp_key", terraformTestPublicKey),
					resource.TestCheckResourceAttr("twistlock_user.test_user", "role", string(model.RoleUser)),
					resource.TestCheckResourceAttr("twistlock_user.test_user", "auth_type", string(model.AuthTypeBasic)),
					testAccUser_GeneratedPassword,
				),
			},
			resource.TestStep{
				Config:      testAccUser_BasicConfig(username+"new", "testdata/test-gpg-keys/terraform.pub", model.RoleUser, model.AuthTypeBasic),
				ExpectError: immutableUsernameError,
			}}})
}

func testAccUserDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(client.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "twistlock_user" {
			continue
		}

		_, found, err := client.ReadUser(rs.Primary.ID)
		if found && err == nil {
			return fmt.Errorf("User still exists")
		}
	}

	return nil
}

func testAccUser_GeneratedPassword(s *terraform.State) error {
	output, ok := s.RootModule().Outputs["password"]
	if !ok {
		return fmt.Errorf("Could not find 'password' output")
	}
	if output.Type != "string" {
		return fmt.Errorf("Expected string output, got: %s", output.Type)
	}

	passwordBytes, err := pgpkeys.DecryptBytes(output.Value.(string), terraformTestPrivateKey)
	if err != nil {
		return err
	}

	password := passwordBytes.String()
	if len(password) != 30 {
		return fmt.Errorf("Expected password of length %d, got %d", 30, len(password))
	}

	return nil
}

func testAccUser_BasicConfig(username, publicKeyFile string, role model.UserRole, auth model.UserAuthType) string {
	return fmt.Sprintf(`
		resource "twistlock_user" "test_user" {
			"username" = "%s"
			"pgp_key" = "${file("%s")}"
			"role" = "%s"
			"auth_type" = "%s"
		}

		output "password" {
			value = "${twistlock_user.test_user.encrypted_password}"
		}`, username, publicKeyFile, role, auth)
}
