package nvdjson

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNVDCVEJSONParse(t *testing.T) {
	f, err := os.Open("testdata/nvdcve-1.1-2018.json.gz")
	if err != nil {
		t.Fatalf("ERROR: %v", err)
	}

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		t.Fatalf("ERROR: %v", err)
	}

	data, err := ioutil.ReadAll(gzReader)
	if err != nil {
		t.Fatalf("ERROR: %v", err)
	}

	var nvdcve NVD
	err = json.Unmarshal(data, &nvdcve)
	if err != nil {
		t.Fatalf("ERROR: %v", err)
	}

	if len(nvdcve.CVEItems) != 16386 {
		t.Fatalf("LEN != 16386")
	}

	checks := []struct {
		CVEId        string
		VendorNames  []string
		ExpectedPath string
		VulnItems    []VulnerableItem
		RefItems     []ReferenceItem
	}{
		{
			CVEId:        "CVE-2018-1000021",
			VendorNames:  []string{"git-scm"},
			ExpectedPath: "testdata/cve-2018-1000021.exp.json",
			VulnItems: []VulnerableItem{
				{CPE23: "cpe:2.3:a:git-scm:git:*:*:*:*:*:*:*:*", VersionEndIncluding: makeStringPtr("2.15.1")},
			},
			RefItems: []ReferenceItem{
				{
					Name:      "http://www.batterystapl.es/2018/01/security-implications-of-ansi-escape.html",
					URL:       "http://www.batterystapl.es/2018/01/security-implications-of-ansi-escape.html",
					RefSource: "MISC",
					Tags:      []string{"Third Party Advisory"},
				},
			},
		},
		{
			CVEId:        "CVE-2018-1000117",
			VendorNames:  []string{"python"},
			ExpectedPath: "testdata/cve-2018-1000117.exp.json",
			VulnItems: []VulnerableItem{
				{CPE23: "cpe:2.3:a:python:python:*:*:*:*:*:*:*:*", VersionStartIncluding: makeStringPtr("3.2.0"), VersionEndIncluding: makeStringPtr("3.6.4")},
				{CPE23: "cpe:2.3:a:python:python:3.7:beta:*:*:*:*:*:*"},
			},
			RefItems: []ReferenceItem{
				{
					Name:      "https://bugs.python.org/issue33001",
					URL:       "https://bugs.python.org/issue33001",
					RefSource: "CONFIRM",
					Tags:      []string{"Issue Tracking", "Patch", "Third Party Advisory"},
				},
				{
					Name:      "https://github.com/python/cpython/pull/5989",
					URL:       "https://github.com/python/cpython/pull/5989",
					RefSource: "CONFIRM",
					Tags:      []string{"Issue Tracking", "Patch", "Vendor Advisory"},
				},
			},
		},
	}

	for _, item := range nvdcve.CVEItems {
		for _, check := range checks {
			if item.CVE.Meta.ID == check.CVEId {
				t.Logf("Processing %s", check.CVEId)
				vulnItems, err := item.VulnerableCPEs()
				if err != nil {
					t.Fatalf("ERROR: %v", err)
				}
				if len(vulnItems) != len(check.VulnItems) {
					t.Fatalf("len(vulnItems) != %d (%d)", len(check.VulnItems), len(vulnItems))
				}
				if !reflect.DeepEqual(vulnItems, check.VulnItems) {
					t.Fatalf("'%#v' != '%#v'\n", vulnItems, check.VulnItems)
				}

				refItems := item.References()
				require.Equal(t, len(check.RefItems), len(refItems))
				require.Equal(t, check.RefItems, refItems)

				var buf bytes.Buffer
				enc := json.NewEncoder(&buf)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "    ")
				err = enc.Encode(item)
				if err != nil {
					t.Fatalf("ERROR: %v", err)
				}

				data := buf.Bytes()

				expected, err := ioutil.ReadFile(check.ExpectedPath)
				if err != nil {
					t.Fatalf("ERROR: %v", err)
				}

				if !bytes.Equal(data, expected) {
					t.Fatalf("ERROR: not as expected")
				}
			}
		}
	}
}

func makeStringPtr(v string) *string {
	return &v
}
