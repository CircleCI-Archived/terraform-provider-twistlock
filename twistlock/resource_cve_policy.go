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
			"rules": {
				Type:     schema.TypeList,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"owner": {
							Type:     schema.TypeString,
							Required: true,
						},
						"name": {
							Type:     schema.TypeString,
							Required: true,
						},
						"resources": {
							Type:     schema.TypeList,
							Required: true,
							MaxItems: 1,
							MinItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"hosts": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"images": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"labels": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
									"containers": {
										Type:     schema.TypeList,
										Optional: true,
										Elem:     &schema.Schema{Type: schema.TypeString},
									},
								},
							},
						},
						"condition": {
							Type:     schema.TypeList,
							Optional: true,
							MaxItems: 1,
							MinItems: 1,
							Elem: &schema.Resource{
								Schema: map[string]*schema.Schema{
									"vulnerabilities": {
										Type:     schema.TypeList,
										Required: true,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"id":               {Type: schema.TypeInt, Required: true},
												"block":            {Type: schema.TypeBool, Required: true},
												"minimum_severity": {Type: schema.TypeFloat, Required: true},
											},
										},
									},
									"cves": {
										Type:     schema.TypeList,
										Required: true,
										MaxItems: 1,
										MinItems: 1,
										Elem: &schema.Resource{
											Schema: map[string]*schema.Schema{
												"ids": {
													Type:     schema.TypeList,
													Required: true,
													Elem:     &schema.Schema{Type: schema.TypeString},
												},
												"effect":     {Type: schema.TypeString, Required: true},
												"only_fixed": {Type: schema.TypeBool, Required: true},
											},
										},
									},
								},
							},
						},
						"block_message": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"verbose": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
					},
				},
			},
		},
	}
}
func cveResourcesFromResource(d map[string]interface{}) map[string][]string {
	converter := func(iface interface{}) []string {
		l := iface.([]interface{})
		slice := make([]string, len(l))
		for i, e := range l {
			slice[i] = e.(string)
		}
		return slice
	}

	var hosts, images, labels, containers []string

	if hs, ok := d["hosts"]; ok {
		hosts = converter(hs)
	}
	if is, ok := d["images"]; ok {
		images = converter(is)
	}
	if ls, ok := d["labels"]; ok {
		labels = converter(ls)
	}
	if cs, ok := d["containers"]; ok {
		containers = converter(cs)
	}

	return map[string][]string{
		"hosts":      hosts,
		"images":     images,
		"labels":     labels,
		"containers": containers,
	}
}

func cveRuleFromResource(d map[string]interface{}) (*model.CVERule, error) {
	var effect model.CVEEffect
	err := effect.UnmarshalText([]byte(d["effect"].(string)))
	if err != nil {
		return &model.CVERule{}, err
	}

	ids := d["ids"].([]interface{})
	stringIDs := make([]string, len(ids))
	for i, id := range ids {
		stringIDs[i] = id.(string)
	}

	return &model.CVERule{
		IDs:       stringIDs,
		Effect:    effect,
		OnlyFixed: d["only_fixed"].(bool),
	}, nil
}

func cveVulnerabilityFromResource(d map[string]interface{}) *model.CVEVulnerability {
	return &model.CVEVulnerability{
		ID:              d["id"].(int),
		Block:           d["block"].(bool),
		MinimumSeverity: model.CVSSv3(d["minimum_severity"].(float64)),
	}
}

func cveConditionFromResource(d map[string]interface{}) (*model.CVECondition, error) {
	cveRuleData := d["cves"].([]interface{})
	cves, err := cveRuleFromResource(cveRuleData[0].(map[string]interface{}))
	if err != nil {
		return &model.CVECondition{}, err
	}

	vulnData := d["vulnerabilities"].([]interface{})
	vulnerabilities := make([]model.CVEVulnerability, len(vulnData))
	for i, resourceData := range vulnData {
		vulnerabilities[i] = *cveVulnerabilityFromResource(resourceData.(map[string]interface{}))
	}

	return &model.CVECondition{
		CVEs:            *cves,
		Vulnerabilities: vulnerabilities,
	}, nil
}

func cvePolicyRuleFromResource(d map[string]interface{}) (*model.CVEPolicyRule, error) {
	resourcesData := d["resources"].([]interface{})

	condition := model.CVECondition{}

	if c, ok := d["condition"]; ok {
		conditionData := c.([]interface{})
		cond, err := cveConditionFromResource(conditionData[0].(map[string]interface{}))
		if err != nil {
			return &model.CVEPolicyRule{}, err
		}
		condition = *cond
	}

	return &model.CVEPolicyRule{
		Owner:        d["owner"].(string),
		Name:         d["name"].(string),
		Resources:    cveResourcesFromResource(resourcesData[0].(map[string]interface{})),
		Condition:    condition,
		BlockMessage: d["block_message"].(string),
		Verbose:      d["verbose"].(bool),
	}, nil
}

func cvePolicyFromResource(d *schema.ResourceData) (*model.CVEPolicy, error) {
	rulesData := d.Get("rules").([]interface{})
	rules := make([]model.CVEPolicyRule, len(rulesData))
	for i, resourceData := range rulesData {
		r, err := cvePolicyRuleFromResource(resourceData.(map[string]interface{}))
		if err != nil {
			return nil, err
		}
		rules[i] = *r
	}

	return &model.CVEPolicy{
		Rules: rules,
	}, nil
}

func resourceCVEPolicyCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(client.Client)

	policy, err := cvePolicyFromResource(d)
	if err != nil {
		return err
	}

	_, err = client.UpdateCVEPolicy(policy)
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

	d.Set("rules", policy.Rules)

	return nil
}

func resourceCVEPolicyUpdate(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("rules") {
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
	_, err := client.UpdateCVEPolicy(&model.CVEPolicy{})
	if err != nil {
		return err
	}

	d.SetId("")

	return nil
}
