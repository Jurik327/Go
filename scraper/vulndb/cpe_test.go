package vulndb

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCPE(t *testing.T) {
	testcases := []struct {
		CPE      string
		Expected CPEParts
	}{
		{
			"cpe:/a:microsoft:internet_explorer:8.0.6001:beta",
			CPEParts{
				CPEVersion: 22,
				Systype:    "a",
				Vendor:     "microsoft",
				Product:    "internet_explorer",
				Version:    "8.0.6001",
				Patch:      "beta",
			},
		},
		{
			"cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*",
			CPEParts{
				CPEVersion: 23,
				Systype:    "a",
				Vendor:     "microsoft",
				Product:    "internet_explorer",
				Version:    "8.0.6001",
				Patch:      "beta",
				Edition:    "*",
				Language:   "*",
				SWEdition:  "*",
				TargetSW:   "*",
				TargetHW:   "*",
				Other:      "*",
			},
		},
		{
			"cpe:/a:adobe:airsdk%26_compiler:18.0.0.180",
			CPEParts{
				CPEVersion: 22,
				Systype:    "a",
				Vendor:     "adobe",
				Product:    "airsdk&_compiler",
				Version:    "18.0.0.180",
			},
		},
		{
			"cpe:2.3:a:hp:insight_diagnostics:8.*:es?:*:-:-:x32:*:*",
			CPEParts{
				CPEVersion: 23,
				Systype:    "a",
				Vendor:     "hp",
				Product:    "insight_diagnostics",
				Version:    "8.*",
				Patch:      "es?",
				Edition:    "*",
				Language:   "-",
				SWEdition:  "-",
				TargetSW:   "x32",
				TargetHW:   "*",
				Other:      "*",
			},
		},
		{
			"cpe:2.3:a:hp:openview_network_manager:7.51:*:*:*:*:linux:*:*",
			CPEParts{
				CPEVersion: 23,
				Systype:    "a",
				Vendor:     "hp",
				Product:    "openview_network_manager",
				Version:    "7.51",
				Patch:      "*",
				Edition:    "*",
				Language:   "*",
				SWEdition:  "*",
				TargetSW:   "linux",
				TargetHW:   "*",
				Other:      "*",
			},
		},
		{

			"cpe:/o:apple:mac_os_x:10.14.3",
			CPEParts{
				CPEVersion: 22,
				Systype:    "o",
				Vendor:     "apple",
				Product:    "mac_os_x",
				Version:    "10.14.3",
			},
		},
		{
			`cpe:2.3:a:foo\\bar:big\$money:2010:*:*:*:special:ipod_touch:80gb:*`,
			CPEParts{
				CPEVersion: 23,
				Systype:    "a",
				Vendor:     `foo\bar`,
				Product:    `big$money`,
				Version:    "2010",
				Patch:      "*",
				Edition:    "*",
				Language:   "*",
				SWEdition:  "special",
				TargetSW:   "ipod_touch",
				TargetHW:   "80gb",
				Other:      "*",
			},
		},
		{
			"cpe:2.3:o:acme:producto:1.0:update2:pro:en-us:*:*:*:*",
			CPEParts{
				CPEVersion: 23,
				Systype:    "o",
				Vendor:     "acme",
				Product:    "producto",
				Version:    "1.0",
				Patch:      "update2",
				Edition:    "pro",
				Language:   "en-us",
				SWEdition:  "*",
				TargetSW:   "*",
				TargetHW:   "*",
				Other:      "*",
			},
		},
		{
			"cpe:2.3:a:archive\\:\\:tar_project:archive\\:\\:tar:*:*:*:*:*:perl:*:*",
			CPEParts{
				CPEVersion: 23,
				Systype:    "a",
				Vendor:     "archive::tar_project",
				Product:    "archive::tar",
				Version:    "*",
				Patch:      "*",
				Edition:    "*",
				Language:   "*",
				SWEdition:  "*",
				TargetSW:   "perl",
				TargetHW:   "*",
				Other:      "*",
			},
		},
	}

	for _, tcase := range testcases {
		cpeParts, err := ParseCPE(tcase.CPE)
		require.NoError(t, err)
		require.Equal(t, tcase.Expected, cpeParts, "CPE: %s", tcase.CPE)
	}
}
