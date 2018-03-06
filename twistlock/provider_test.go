package twistlock

import (
	"os"
	"testing"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

var testAccProviders map[string]terraform.ResourceProvider
var testAccProvider *schema.Provider

func init() {
	testAccProvider = Provider()
	testAccProviders = map[string]terraform.ResourceProvider{
		"twistlock": testAccProvider,
	}
}

func testAccPreCheck(t *testing.T) {
	if os.Getenv("TWISTLOCK_USERNAME") == "" {
		t.Fatalf("TWISTLOCK_USERNAME must be set")
	}

	if os.Getenv("TWISTLOCK_PASSWORD") == "" {
		t.Fatalf("TWISTLOCK_PASSWORD must be set")
	}

	if os.Getenv("TWISTLOCK_BASE_URL") == "" {
		t.Fatalf("TWISTLOCK_BASE_URL must be set, e.g. http://localhost:8081/api/v1")
	}
}

func TestProvider(t *testing.T) {
	if err := Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}
