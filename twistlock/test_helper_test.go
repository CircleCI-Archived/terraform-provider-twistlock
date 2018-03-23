package twistlock

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAttrLeaf(t *testing.T) {
	assert := assert.New(t)

	rs := AttrLeaf("hi").Walk()
	assert.Equal([]walkResult{{"", "hi"}}, rs)
}

func TestAttrList(t *testing.T) {
	assert := assert.New(t)

	rs := AttrList{AttrLeaf("hi"), AttrLeaf("world")}.Walk()
	assert.Equal([]walkResult{{"#", "2"}, {"0", "hi"}, {"1", "world"}}, rs)
}

func TestAttrMap(t *testing.T) {
	assert := assert.New(t)

	rs := AttrMap{
		"foo": AttrLeaf("bar"),
		"bar": AttrList{AttrLeaf("baz")},
		"baz": AttrMap{
			"qux": AttrLeaf("foo"),
		},
	}.Walk()
	sort.Sort(byWalkResult(rs))

	expected := []walkResult{
		{"bar.#", "1"},
		{"bar.0", "baz"},
		{"baz.qux", "foo"},
		{"foo", "bar"},
	}
	assert.Equal(expected, rs)
}

func TestRealWorldScenario(t *testing.T) {
	assert := assert.New(t)

	s := AttrMap{
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
			}}}

	rs := s.Walk()
	sort.Sort(byWalkResult(rs))

	expected := []walkResult{
		{"rules.#", "1"},
		{"rules.0.block_message", ""},
		{"rules.0.condition.#", "1"},
		{"rules.0.condition.0.cves.#", "1"},
		{"rules.0.condition.0.cves.0.effect", "alert"},
		{"rules.0.condition.0.cves.0.ids.#", "1"},
		{"rules.0.condition.0.cves.0.ids.0", "CVE-2017-1234"},
		{"rules.0.condition.0.cves.0.only_fixed", "true"},
		{"rules.0.condition.0.vulnerabilities.#", "1"},
		{"rules.0.condition.0.vulnerabilities.0.block", "true"},
		{"rules.0.condition.0.vulnerabilities.0.id", "46"},
		{"rules.0.condition.0.vulnerabilities.0.minimum_severity", "9"},
		{"rules.0.name", "Twistlock acceptance test CVE policy"},
		{"rules.0.owner", "test_user"},
		{"rules.0.resources.#", "1"},
		{"rules.0.resources.0.containers.#", "1"},
		{"rules.0.resources.0.containers.0", "*"},
		{"rules.0.resources.0.hosts.#", "1"},
		{"rules.0.resources.0.hosts.0", "*"},
		{"rules.0.resources.0.images.#", "2"},
		{"rules.0.resources.0.images.0", "*"},
		{"rules.0.resources.0.images.1", "foo/*"},
		{"rules.0.resources.0.labels.#", "1"},
		{"rules.0.resources.0.labels.0", "*"},
		{"rules.0.verbose", "true"},
	}

	assert.Equal(expected, rs)
}
