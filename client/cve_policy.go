package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/circleci/terraform-provider-twistlock/model"
)

var cvePolicyPath = "/policies/cve"

func (c *Client) UpdateCVEPolicy(p *model.CVEPolicy) (model.CVEPolicy, error) {
	url := c.baseURL + cvePolicyPath
	p.PolicyType = "cve"
	p.ID = "cve"
	policyJson, err := json.Marshal(p)
	if err != nil {
		return model.CVEPolicy{}, err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(policyJson))
	if err != nil {
		return model.CVEPolicy{}, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return model.CVEPolicy{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return model.CVEPolicy{}, fmt.Errorf("Failed to update CVE policy: %s", string(body))
	}

	policy, err := c.ReadCVEPolicy()
	if err != nil {
		return model.CVEPolicy{}, fmt.Errorf("CVE policy update failed, could not fetch after update: %s", err)
	}

	return policy, nil
}

func (c *Client) ReadCVEPolicy() (model.CVEPolicy, error) {
	url := c.baseURL + cvePolicyPath
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return model.CVEPolicy{}, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.http.Do(req)
	if err != nil {
		return model.CVEPolicy{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return model.CVEPolicy{}, fmt.Errorf("Failed to read CVE policy: %s", string(body))
	}

	cvePolicy := model.CVEPolicy{}

	decoder := json.NewDecoder(resp.Body)
	if err = decoder.Decode(&cvePolicy); err != nil {
		return model.CVEPolicy{}, err
	}

	return cvePolicy, nil
}
