package twistlock

import (
	"fmt"
	"testing"

	"github.com/circleci/terraform-provider-twistlock/client"
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
				Config: testAccMachineUser_BasicConfig(username, password),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "username", username),
					resource.TestCheckResourceAttr("twistlock_machine_user.test_user", "password", password),
				),
			},
		},
	})
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

func testAccMachineUser_BasicConfig(username, password string) string {
	return fmt.Sprintf(`
		resource "twistlock_machine_user" "test_user" {
			"username" = "%s"
			"password" = "%s"
			"role" = "defenderManager"
			"auth_type" = "basic"
		  }`, username, password)
}
