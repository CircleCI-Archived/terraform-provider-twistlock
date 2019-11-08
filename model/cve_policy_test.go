package model

import (
	"reflect"
	"testing"
)

func TestConverter(t *testing.T) {
	cases := []struct {
		input    []string
		expected []interface{}
	}{
		{
			[]string{},
			[]interface{}{},
		},
		{
			[]string{"a", "b", "c"},
			[]interface{}{"a", "b", "c"},
		},
	}

	for _, c := range cases {
		actual := converter(c.input)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("Actual = %v; Expected = %v", actual, c.expected)
		}
	}
}

func TestFlattenRuleResources(t *testing.T) {
	cases := []struct {
		input    map[string][]string
		expected []interface{}
	}{
		{
			map[string][]string{
				"hosts":      []string{"a", "b", "c"},
				"images":     []string{"a", "b", "c"},
				"labels":     []string{"a", "b", "c"},
				"containers": []string{"a", "b", "c"},
			},
			[]interface{}{
				map[string][]interface{}{
					"hosts":      converter([]string{"a", "b", "c"}),
					"images":     converter([]string{"a", "b", "c"}),
					"labels":     converter([]string{"a", "b", "c"}),
					"containers": converter([]string{"a", "b", "c"}),
				},
			},
		},
	}

	for _, c := range cases {
		actual := flattenRuleResources(c.input)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("Actual = %v; Expected = %v", actual, c.expected)
		}
	}
}

func TestFlattenCVEVul(t *testing.T) {
	cases := []struct {
		input    CVEVulnerability
		expected map[string]interface{}
	}{
		{
			CVEVulnerability{
				ID:              410,
				Block:           false,
				MinimumSeverity: CVSSv3(0),
			},
			map[string]interface{}{
				"id":               410,
				"block":            false,
				"minimum_severity": CVSSv3(0),
			},
		},
	}

	for _, c := range cases {
		actual := flattenCVEVul(c.input)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("Actual = %v; Expected = %v", actual, c.expected)
		}
	}
}

func TestFlattenRuleConditionVulnerabilities(t *testing.T) {
	cases := []struct {
		input    []CVEVulnerability
		expected []interface{}
	}{
		{
			[]CVEVulnerability{
				CVEVulnerability{
					ID:              410,
					Block:           false,
					MinimumSeverity: CVSSv3(0),
				},
				CVEVulnerability{
					ID:              411,
					Block:           true,
					MinimumSeverity: CVSSv3(10),
				},
			},
			[]interface{}{
				flattenCVEVul(
					CVEVulnerability{
						ID:              410,
						Block:           false,
						MinimumSeverity: CVSSv3(0),
					},
				),
				flattenCVEVul(
					CVEVulnerability{
						ID:              411,
						Block:           true,
						MinimumSeverity: CVSSv3(10),
					},
				),
			},
		},
	}

	for _, c := range cases {
		actual := flattenRuleConditionVulnerabilities(c.input)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("Actual = %v; Expected = %v", actual, c.expected)
		}
	}
}

func TestFlattenRuleConditionCVEs(t *testing.T) {
	cases := []struct {
		input    CVERule
		expected []interface{}
	}{
		{
			CVERule{
				IDs:       []string{"a", "b", "c"},
				Effect:    CVEEffect("ignore"),
				OnlyFixed: false,
			},
			[]interface{}{
				map[string]interface{}{
					"ids":        converter([]string{"a", "b", "c"}),
					"effect":     CVEEffect("ignore"),
					"only_fixed": false,
				},
			},
		},
	}

	for _, c := range cases {
		actual := flattenRuleConditionCVEs(c.input)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("Actual = %v; Expected = %v", actual, c.expected)
		}
	}
}

func TestFlattenRuleCondition(t *testing.T) {
	cases := []struct {
		input    CVECondition
		expected []interface{}
	}{
		{
			CVECondition{
				Vulnerabilities: []CVEVulnerability{
					CVEVulnerability{
						ID:              410,
						Block:           false,
						MinimumSeverity: CVSSv3(0),
					},
				},
				CVEs: CVERule{
					IDs:       []string{"a", "b", "c"},
					Effect:    CVEEffect("ignore"),
					OnlyFixed: false,
				},
			},
			[]interface{}{
				map[string]interface{}{
					"vulnerabilities": []interface{}{
						flattenCVEVul(
							CVEVulnerability{
								ID:              410,
								Block:           false,
								MinimumSeverity: CVSSv3(0),
							},
						),
					},
					"cves": []interface{}{
						map[string]interface{}{
							"ids":        converter([]string{"a", "b", "c"}),
							"effect":     CVEEffect("ignore"),
							"only_fixed": false,
						},
					},
				},
			},
		},
	}

	for _, c := range cases {
		actual := flattenRuleCondition(c.input)
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("Actual = %v; Expected = %v", actual, c.expected)
		}
	}
}

func TestFlatten(t *testing.T) {
	cases := []struct {
		input    CVEPolicyRule
		expected map[string]interface{}
	}{
		{
			CVEPolicyRule{
				Owner: "systems",
				Name:  "Default - alert all components",
				Resources: map[string][]string{
					"hosts":      []string{"*"},
					"images":     []string{"*"},
					"labels":     []string{"*"},
					"containers": []string{"*"},
				},
				Condition: CVECondition{
					Vulnerabilities: []CVEVulnerability{
						CVEVulnerability{
							ID:              410,
							Block:           false,
							MinimumSeverity: CVSSv3(0),
						},
					},
					CVEs: CVERule{
						IDs:       []string{"a", "b", "c"},
						Effect:    CVEEffect("ignore"),
						OnlyFixed: false,
					},
				},
				Verbose: false,
			},
			map[string]interface{}{
				"owner": "systems",
				"name":  "Default - alert all components",
				"resources": []interface{}{
					map[string][]interface{}{
						"hosts":      converter([]string{"*"}),
						"images":     converter([]string{"*"}),
						"labels":     converter([]string{"*"}),
						"containers": converter([]string{"*"}),
					},
				},
				"condition": []interface{}{
					map[string]interface{}{
						"vulnerabilities": []interface{}{
							flattenCVEVul(
								CVEVulnerability{
									ID:              410,
									Block:           false,
									MinimumSeverity: CVSSv3(0),
								},
							),
						},
						"cves": []interface{}{
							map[string]interface{}{
								"ids":        converter([]string{"a", "b", "c"}),
								"effect":     CVEEffect("ignore"),
								"only_fixed": false,
							},
						},
					},
				},
				"block_message": "",
				"verbose":       false,
			},
		},
	}

	for _, c := range cases {
		actual := c.input.Flatten()
		if !reflect.DeepEqual(actual, c.expected) {
			t.Errorf("\nActual = %v;\nExpected = %v", actual, c.expected)
		}
	}
}
