package model

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
	PolicyJSON string
}
