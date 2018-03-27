package twistlock

import (
	"log"

	"github.com/circleci/terraform-provider-twistlock/client"
	"github.com/circleci/terraform-provider-twistlock/model"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceCVEPolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceCVEPolicyCreate,
		Read:   resourceCVEPolicyRead,
		Update: resourceCVEPolicyUpdate,
		Delete: resourceCVEPolicyDelete,

		Schema: map[string]*schema.Schema{
			"policy_json": {
				Type:     schema.TypeString,
				Required: true,
			},
		},
	}
}

func cvePolicyFromResource(d *schema.ResourceData) (model.CVEPolicy, error) {
	return model.CVEPolicy{
		PolicyJSON: d.Get("policy_json").(string),
	}, nil
}

func resourceCVEPolicyCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)

	policy, err := cvePolicyFromResource(d)
	if err != nil {
		return err
	}

	_, err = client.UpdateCVEPolicy(&policy)
	if err != nil {
		return err
	}

	d.SetId("cve_policy")

	return nil
}

func resourceCVEPolicyRead(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)

	policy, err := client.ReadCVEPolicy()
	if err != nil {
		return err
	}

	d.Set("policy_json", string(policy.PolicyJSON))

	return nil
}

func resourceCVEPolicyUpdate(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("policy_json") {
		err := resourceCVEPolicyCreate(d, m)
		if err != nil {
			return err
		}
	}

	return resourceCVEPolicyRead(d, m)
}

func resourceCVEPolicyDelete(d *schema.ResourceData, m interface{}) error {
	log.Print("[WARN] Cannot destroy the Twistlock CVE policy. Setting an empty policy.")

	client := m.(client.Client)
	_, err := client.UpdateCVEPolicy(&model.CVEPolicy{
		PolicyJSON: `{
			"version": "",
			"rules": [],
			"policyType": "cve",
			"_id": "cve"
		}`,
	})
	if err != nil {
		return err
	}

	d.SetId("")
	return nil
}
