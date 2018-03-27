package twistlock

import (
	"encoding/json"
	"fmt"
	"reflect"
	"regexp"
	"testing"

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
				/*Check: testAccCheckCreated(model.CVEPolicy{
					PolicyJSON: `
						{
							"version": "",
							"rules": [{
								"owner": "test_user",
								"name": "Twistlock acceptance test CVE policy",
								"modified":"2018-03-27T10:21:54.85Z",
								"resources": {
									"hosts": ["*"],
									"images": ["*", "foo/*"],
									"labels": ["*"],
									"containers": ["*"]
								},
								"condition": {
									"vulnerabilities": [
										{"id": 46, "block": true, "minSeverity": 9}
									],
									"cves": {
										"ids": ["CVE-2017-1234"],
										"effect": "alert",
										"onlyFixed": true
									}
								},
								"verbose": true
							}],
							"policyType": "cve",
							"_id": "cve"
						}`,
				}),*/
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

		expected := map[string]interface{}{}
		actual := map[string]interface{}{}

		err = json.Unmarshal([]byte(expectedPolicy.PolicyJSON), &expected)
		if err != nil {
			return err
		}

		err = json.Unmarshal([]byte(policy.PolicyJSON), &actual)
		if err != nil {
			return err
		}

		stripUnusedFields(expected)
		stripUnusedFields(actual)

		if !reflect.DeepEqual(expected, actual) {
			return fmt.Errorf("incorrect rule resources, expected: %#v, got: %#v", expected, actual)
		}

		return nil
	}
}

func testAccCVEPolicyDestroy(s *terraform.State) error {
	client := testAccProvider.Meta().(client.Client)

	p, err := client.ReadCVEPolicy()
	if err != nil {
		return err
	}

	policy := map[string]interface{}{}
	err = json.Unmarshal([]byte(p.PolicyJSON), &policy)
	if err != nil {
		return err
	}

	if len(policy["rules"].([]interface{})) > 0 {
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
		policy_json = <<EOF
	{
		"version": "",
		"rules": [{
			"owner": "test_user",
			"name": "Twistlock acceptance test CVE policy",
			"modified":"2018-03-27T10:21:54.85Z",
			"resources": {
				"hosts": ["*"],
				"images": ["*", "foo/*"],
				"labels": ["*"],
				"containers": ["*"]
			},
			"condition": {
				"vulnerabilities": [
					{"id": 46, "block": true, "minSeverity": 9}
				],
				"cves": {
					"ids": ["CVE-2017-1234"],
					"effect": "alert",
					"onlyFixed": true
				}
			},
			"verbose": true
		}],
		"policyType": "cve",
		"_id": "cve"
	}
	EOF
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
		policy_json = <<EOF
	{
		"version": "",
		"rules": [{
			"owner": "test_user",
			"name": "Twistlock acceptance test CVE policy",
			"modified":"2018-03-27T10:21:54.85Z",
			"resources": {
				"hosts": ["foo/*"],
				"images": ["*"],
				"labels": ["*"],
				"containers": ["*"]
			},
			"condition": {
				"vulnerabilities": [
					{"id": 46, "block": true, "minSeverity": 7},
					{"id": 413, "block": false, "minSeverity": 9}
				],
				"cves": {
					"ids": ["CVE-2017-1234", "CVE-2017-2308"],
					"effect": "ignore",
					"onlyFixed": false
				},
			},
			"verbose": "true",
			"blockMsg": "Not permitted"
		}],
		"policyType": "cve",
		"_id": "cve"
	}
	EOF
	}`
}

func testAccCVEPolicyThereCanBeOnlyOne(t *testing.T) {
	tooManyCVEPoliciesError, err := regexp.Compile("Only one CVE policy can be configured")
	if err != nil {
		t.Fatal("Could not compile CVE policy count check regular expression")
	}

	resource.Test(t, resource.TestCase{
		PreCheck: func() {
			testAccPreCheck(t)
		},
		CheckDestroy: testAccCVEPolicyDestroy,
		Providers:    testAccProviders,
		Steps: []resource.TestStep{
			resource.TestStep{
				Config:      testAccCVEPolicy_TooManyCVEPoliciesConfig(),
				ExpectError: tooManyCVEPoliciesError,
			},
		},
	})
}

func testAccCVEPolicy_TooManyCVEPoliciesConfig() string {
	return `
	resource "twistlock_machine_user" "test_user" {
		"username" = "test-user"
		"password" = "password"
		"role" = "admin"
		"auth_type" = "basic"
	}

	resource "twistlock_cve_policy" "test_cve_policy" {
		rules = <<EOF
	[{
		"owner": "test_user"
		"name": "Twistlock acceptance test CVE policy"
		"resources": {
			"hosts": ["*"]
			"images": ["*"]
			"labels": ["*"]
			"containers": ["*"]
		},
		"condition": {
			"vulnerabilities": [
				{"id": 46, "block": true, "minSeverity": 9}
			]
			"cves": {
				"ids": ["CVE-2017-1234"]
				"effect": "alert"
				"only_fixed": true
			}
		}
		"verbose": "true"
	}]
	EOF
	}

	resource "twistlock_cve_policy" "system_ignore_twistlock_policy" {
		rules = <<EOF
	[{
		"owner": "system"
		"name": "Default - ignore Twistlock components"
		"resources": {
			"hosts": ["*"]
			"images": ["twistlock*"]
			"labels": ["*"]
			"containers": ["*"]
		}
		"condition": {
			"vulnerabilities": [
				{"id": 46, "block": true, "minSeverity": 9}
			]
			"cves": {
				"ids": ["CVE-2017-1234"]
				"effect": "alert"
				"onlyFixed": true
			}
		}
		"verbose": "true"
	}]
	EOF
	}`
}

// stripUnusedFields removes not-applicable or unused fields from the policy rules.
//
// See https://twistlock.desk.com/customer/en/portal/articles/2912404-twistlock-api-2-3?b_id=16619#policies_cve_get
func stripUnusedFields(policy map[string]interface{}) {
	for _, r := range policy["rules"].([]interface{}) {
		m := r.(map[string]interface{})
		delete(m, "previousName")
		delete(m, "action")
		delete(m, "group")
		delete(m, "namespace")

		c := m["condition"].(map[string]interface{})
		delete(c, "readonly")
		delete(c, "device")
		delete(c, "envVars")
	}
}
