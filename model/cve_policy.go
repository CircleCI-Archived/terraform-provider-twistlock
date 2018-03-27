package model

import (
	"fmt"
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
