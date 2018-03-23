package twistlock

import (
	"fmt"
	"regexp"
	"testing"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/circleci/terraform-provider-twistlock/model"
	"github.com/hashicorp/terraform/helper/acctest"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccMachineUser(t *testing.T) {
	username := acctest.RandString(8)
	password := acctest.RandString(10)

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		CheckDestroy: testAccMachineUserDestroy,
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccMachineUser_BasicConfig(username, password, model.RoleUser, model.AuthTypeBasic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "username", username),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "password", password),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "role", string(model.RoleUser)),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "auth_type", string(model.AuthTypeBasic)),
				),
			},
			// Update role
			resource.TestStep{
				Config: testAccMachineUser_BasicConfig(username, password, model.RoleDefenderManager, model.AuthTypeBasic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "username", username),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "password", password),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "role", string(model.RoleDefenderManager)),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "auth_type", string(model.AuthTypeBasic)),
				),
			},
			// Update password
			resource.TestStep{
				Config: testAccMachineUser_BasicConfig(username, password+"new", model.RoleDefenderManager, model.AuthTypeBasic),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "username", username),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "password", password+"new"),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "role", string(model.RoleDefenderManager)),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "auth_type", string(model.AuthTypeBasic)),
				),
			},
		},
	})
}

func TestAccMachineUser_CannotMutateImmutableUserProperties(t *testing.T) {
	username := acctest.RandString(8)
	password := acctest.RandString(10)

	immutableUsernameError, err := regexp.Compile("Twistlock usernames are immutable")
	if err != nil {
		t.Fatal("Could not compile username check regular expression")
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		CheckDestroy: testAccUserDestroy,
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccMachineUser_BasicConfig(username, password, model.RoleUser, model.AuthTypeBasic),
				Check: CheckTerraformState("twistlock_machine_user.test_user", AttrMap{
					"username":  AttrLeaf(username),
					"password":  AttrLeaf(password),
					"role":      AttrLeaf(model.RoleUser),
					"auth_type": AttrLeaf(model.AuthTypeBasic),
				}),
			},
			resource.TestStep{
				Config:      testAccMachineUser_BasicConfig(username+"new", password, model.RoleUser, model.AuthTypeBasic),
				ExpectError: immutableUsernameError,
			}}})
}

func testAccMachineUserDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(client.Client)

	for _, rs := range s.RootModule().Resources {
		if rs.Type != "twistlock_machine_user" {
			continue
		}

		_, found, err := client.ReadUser(rs.Primary.ID)
		if found && err == nil {
			return fmt.Errorf("User still exists")
		}
	}

	return nil
}

func testAccMachineUser_BasicConfig(username, password string, role model.UserRole, auth model.UserAuthType) string {
	return fmt.Sprintf(`
		resource "twistlock_machine_user" "test_user" {
			"username" = "%s"
			"password" = "%s"
			"role" = "%s"
			"auth_type" = "%s"
		  }`, username, password, role, auth)
}
