package twistlock

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/circleci/terraform-provider-twistlock/model"
	"github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestAccCVEPolicy(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		CheckDestroy: testAccCVEPolicyDestroy,
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config: testAccCVEPolicy_BasicConfig(),
				Check: resource.ComposeTestCheckFunc(
					CheckTerraformState("twistlock_cve_policy.test_cve_policy", AttrMap{
						"rules": AttrList{
							AttrMap{
								"owner":         AttrLeaf("test_user"),
								"name":          AttrLeaf("Twistlock acceptance test CVE policy"),
								"verbose":       AttrLeaf("true"),
								"block_message": AttrLeaf(""),
								"resources": AttrList{
									AttrMap{
										"hosts":      AttrList{AttrLeaf("*")},
										"images":     AttrList{AttrLeaf("*"), AttrLeaf("foo/*")},
										"labels":     AttrList{AttrLeaf("*")},
										"containers": AttrList{AttrLeaf("*")},
									},
								},
								"condition": AttrList{
									AttrMap{
										"vulnerabilities": AttrList{
											AttrMap{
												"id":               AttrLeaf("46"),
												"block":            AttrLeaf("true"),
												"minimum_severity": AttrLeaf("9"),
											}},
										"cves": AttrList{
											AttrMap{
												"ids":        AttrList{AttrLeaf("CVE-2017-1234")},
												"effect":     AttrLeaf("alert"),
												"only_fixed": AttrLeaf("true"),
											},
										},
									},
								},
							}}}),
					testAccCheckCreated(model.CVEPolicy{
						Rules: []model.CVEPolicyRule{{
							Modified: time.Time{},
							Owner:    "test_user",
							Name:     "Twistlock acceptance test CVE policy",
							Resources: map[string][]string{
								"hosts":      {"*"},
								"images":     {"*", "foo/*"},
								"containers": {"*"},
								"labels":     {"*"},
							},
							Condition: model.CVECondition{
								Vulnerabilities: []model.CVEVulnerability{
									{ID: 46, Block: true, MinimumSeverity: 9},
								},
								CVEs: model.CVERule{
									IDs:       []string{"CVE-2017-1234"},
									Effect:    model.CVEEffectAlert,
									OnlyFixed: true,
								},
							},
							Verbose: true,
						}},
						PolicyType: "cve",
						ID:         "cve",
					}),
				),
			},
			resource.TestStep{
				Config: testAccCVEPolicy_UpdateConfig(),
				Check: resource.ComposeTestCheckFunc(
					CheckTerraformState("twistlock_cve_policy.test_cve_policy", AttrMap{
						"rules": AttrList{
							AttrMap{
								"owner":         AttrLeaf("test_user"),
								"name":          AttrLeaf("Twistlock acceptance test CVE policy"),
								"verbose":       AttrLeaf("true"),
								"block_message": AttrLeaf("Not permitted"),
								"resources": AttrList{
									AttrMap{
										"hosts":      AttrList{AttrLeaf("foo/*")},
										"images":     AttrList{AttrLeaf("*")},
										"labels":     AttrList{AttrLeaf("*")},
										"containers": AttrList{AttrLeaf("*")},
									},
								},
								"condition": AttrList{
									AttrMap{
										"vulnerabilities": AttrList{
											AttrMap{
												"id":               AttrLeaf("46"),
												"block":            AttrLeaf("true"),
												"minimum_severity": AttrLeaf("7"),
											},
											AttrMap{
												"id":               AttrLeaf("413"),
												"block":            AttrLeaf("false"),
												"minimum_severity": AttrLeaf("9"),
											}},
										"cves": AttrList{
											AttrMap{
												"ids":        AttrList{AttrLeaf("CVE-2017-1234"), AttrLeaf("CVE-2017-2308")},
												"effect":     AttrLeaf("ignore"),
												"only_fixed": AttrLeaf("false"),
											},
										},
									},
								},
							}}}),
					testAccCheckCreated(model.CVEPolicy{
						Rules: []model.CVEPolicyRule{{
							Modified:     time.Time{},
							Owner:        "test_user",
							Name:         "Twistlock acceptance test CVE policy",
							BlockMessage: "Not permitted",
							Resources: map[string][]string{
								"hosts":      {"foo/*"},
								"images":     {"*"},
								"containers": {"*"},
								"labels":     {"*"},
							},
							Condition: model.CVECondition{
								Vulnerabilities: []model.CVEVulnerability{
									{ID: 46, Block: true, MinimumSeverity: 7},
									{ID: 413, Block: false, MinimumSeverity: 9},
								},
								CVEs: model.CVERule{
									IDs:       []string{"CVE-2017-1234", "CVE-2017-2308"},
									Effect:    model.CVEEffectIgnore,
									OnlyFixed: false,
								},
							},
							Verbose: true,
						}},
						PolicyType: "cve",
						ID:         "cve",
					}),
				),
			},
		},
	})
}

func testAccCheckCreated(expectedPolicy model.CVEPolicy) func(s *terraform.State) error {
	return func(s *terraform.State) error {
		client := testAccProvider.Meta().(client.Client)

		policy, err := client.ReadCVEPolicy()
		if err != nil {
			return err
		}

		if len(policy.Rules) != 1 {
			return fmt.Errorf("found no policy rules")
		}

		// zero out the rule modified time, it's unpredictable
		policy.Rules[0].Modified = time.Time{}

		if !reflect.DeepEqual(expectedPolicy, policy) {
			return fmt.Errorf("incorrect rule resources, expected: %v, got: %v", expectedPolicy, policy)
		}

		return nil
	}
}

func testAccCVEPolicyDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(client.Client)

	cvePolicy, err := client.ReadCVEPolicy()
	if err != nil {
		return err
	}

	if len(cvePolicy.Rules) > 0 {
		return fmt.Errorf("CVE Policy was not zeroed")
	}

	return nil
}

func testAccCVEPolicy_BasicConfig() string {
	return `
	resource "twistlock_machine_user" "test_user" {
		"username" = "test-user"
		"password" = "password"
		"role" = "admin"
		"auth_type" = "basic"
	}

	resource "twistlock_cve_policy" "test_cve_policy" {
		rules = [
			{"owner" = "test_user"
			 "name" = "Twistlock acceptance test CVE policy"
			 "resources" {
			 	"hosts" = ["*"]
			 	"images" = ["*", "foo/*"]
			 	"labels" = ["*"]
			 	"containers" = ["*"]
			 }
			 "condition" = {
			 	"vulnerabilities" = [
				 	{"id" = 46, "block" = true, "minimum_severity" = 9}
			 	]
				"cves" = {
				 	"ids" = ["CVE-2017-1234"]
				 	"effect" = "alert"
				 	"only_fixed" = true
			 	}
			}
			"verbose" = "true"}
		]
	}`
}

func testAccCVEPolicy_UpdateConfig() string {
	return `
	resource "twistlock_machine_user" "test_user" {
		"username" = "test-user"
		"password" = "password"
		"role" = "admin"
		"auth_type" = "basic"
	}

	resource "twistlock_cve_policy" "test_cve_policy" {
		rules = [
			{"owner" = "test_user"
			 "name" = "Twistlock acceptance test CVE policy"
			 "resources" {
			 	"hosts" = ["foo/*"]
			 	"images" = ["*"]
			 	"labels" = ["*"]
			 	"containers" = ["*"]
			 }
			 "condition" = {
			 	"vulnerabilities" = [
					{"id" = 46, "block" = true, "minimum_severity" = 7},
					{"id" = 413, "block" = false, "minimum_severity" = 9}
			 	]
				"cves" = {
				 	"ids" = ["CVE-2017-1234", "CVE-2017-2308"]
				 	"effect" = "ignore"
				 	"only_fixed" = false
			 	}
			}
			"verbose" = "true"
			"block_message" = "Not permitted"}
		]
	}`
}
