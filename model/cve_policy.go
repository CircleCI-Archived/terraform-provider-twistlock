package model

import (
	"fmt"
	"log"
	"time"
)

type CVEPolicyService interface {
	CreateCVEPolicy(p *CVEPolicy) (CVEPolicy, error)
	UpdateCVEPolicy(p *CVEPolicy) (CVEPolicy, error)
	DeleteCVEPolicy(p *CVEPolicy) (CVEPolicy, error)
	ReadCVEPolicy(name string) (CVEPolicy, error)
}

// CVEPolicy is a Twistlock CVE policy.
//
// See https://twistlock.desk.com/customer/en/portal/articles/2912404-twistlock-api-2-3?b_id=16619#policies_cve_get
type CVEPolicy struct {
	Rules []CVEPolicyRule
	// PolicyType must always be "cve"
	PolicyType string
	// ID must always be "cve"
	ID string `json:"_id"`
}

// CVEPolicyRule represents a single rule in a Twistlock CVE policy.
type CVEPolicyRule struct {
	// Ignored fields from the Twistlock API response:
	//
	// Effect    - can't be changed
	// Action    - unused
	// Group     - unused
	// Namespace - unused
	Modified     time.Time
	Owner        string
	Name         string
	PreviousName string `json:",omitempty"`
	Resources    map[string][]string
	Condition    CVECondition
	BlockMessage string `json:"blockMsg,omitempty"`
	Verbose      bool
}

// CVECondition is the specific rule configuration for a CVEPolicyRule.
type CVECondition struct {
	// Ignored fields from the Twistlock API response:
	//
	// ReadOnly - unused
	// Device   - unused
	// EnvVars	- unused
	Vulnerabilities []CVEVulnerability
	CVEs            CVERule
}

// CVEVulnerability is a specifies the action to take for different categories
// of vulnerability that Twistlock can detect.
//
// Categories are represented by integer IDs, see the main Twistlock CVE Policy
// documentation for possible values.
type CVEVulnerability struct {
	ID              int
	Block           bool
	MinimumSeverity CVSSv3 `json:"minSeverity"`
}

// CVSSv3 represents a CVSS v3 severity rating.
// See https://www.first.org/cvss/specification-document#5-Qualitative-Severity-Rating-Scale
//
// Twistlock uses a subset of all possible values:
// 0 - low
// 4 - medium
// 7 - high
// 9 - critical
type CVSSv3 float64

type CVERule struct {
	IDs       []string
	Effect    CVEEffect
	OnlyFixed bool
}

type CVEEffect string

const (
	CVEEffectIgnore = "ignore"
	CVEEffectAlert  = "alert"
	CVEEffectBlock  = "block"
	CVEEffectEmpty  = ""
)

func (e *CVEEffect) UnmarshalText(text []byte) error {
	switch string(text) {
	case "ignore":
		*e = CVEEffectIgnore
	case "alert":
		*e = CVEEffectAlert
	case "block":
		*e = CVEEffectBlock
	case "":
		*e = CVEEffectEmpty
	default:
		return fmt.Errorf("Invalid CVE Effect: %s", string(text))
	}
	return nil
}

func converter(values []string) []interface{} {
	slice := make([]interface{}, len(values))
	for i, e := range values {
		slice[i] = e
	}
	return slice
}

func flattenRuleResources(resources map[string][]string) []interface{} {
	m := make(map[string][]interface{})
	m["hosts"] = converter(resources["hosts"])
	m["images"] = converter(resources["images"])
	m["labels"] = converter(resources["labels"])
	m["containers"] = converter(resources["containers"])
	return []interface{}{m}
}

func flattenCVEVul(v CVEVulnerability) map[string]interface{} {
	out := make(map[string]interface{})
	out["id"] = v.ID
	out["block"] = v.Block
	out["minimum_severity"] = v.MinimumSeverity
	return out
}

func flattenRuleConditionVulnerabilities(vuln []CVEVulnerability) []interface{} {
	m := make([]interface{}, len(vuln), len(vuln))

	for i, v := range vuln {
		m[i] = flattenCVEVul(v)
	}

	return m
}

func flattenRuleConditionCVEs(cves CVERule) []interface{} {
	m := make(map[string]interface{})
	m["ids"] = converter(cves.IDs)
	m["effect"] = cves.Effect
	m["only_fixed"] = cves.OnlyFixed

	log.Printf("[INFO] flattenRuleConditionCVEs - m is %v", m)

	return []interface{}{m}
}

func flattenRuleCondition(condition CVECondition) []interface{} {
	m := make(map[string]interface{})
	m["vulnerabilities"] = flattenRuleConditionVulnerabilities(condition.Vulnerabilities)
	m["cves"] = flattenRuleConditionCVEs(condition.CVEs)
	return []interface{}{m}
}

// Flatten returns flattened data structure used to refresh in-memory resourceData
func (rule CVEPolicyRule) Flatten() map[string]interface{} {
	m := make(map[string]interface{})
	m["owner"] = rule.Owner
	m["name"] = rule.Name
	m["resources"] = flattenRuleResources(rule.Resources)
	m["condition"] = flattenRuleCondition(rule.Condition)
	m["block_message"] = rule.BlockMessage
	m["verbose"] = rule.Verbose

	return m
}
