package vulndb

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	reVersionParts = regexp.MustCompile(`([\d]+)\.?([\d]+)?\(?([\d]+)?\)?([a-zA-Z]+)?\.?([a-zA-Z]+)?([\d]+)?\.?([\d]+)?\.?([\d]+)?-?([a-z]?)([\d]+)?`)
)

// VersionCompare compares `targetVer` against `templateVer` and returns
// -1, 0, or 1 if the target version is smaller, equal or larger, or
// 2 if the versions are not compatible/i.e. should not be matched.
//
// NOTE: This version matching is designed for matching products against a template
// for determining vulnerability matching.
// See TestVersionCompare test case for specific examples.
func VersionCompare(templateVer, targetVer string) int {
	templateVer = strings.TrimSpace(templateVer)
	targetVer = strings.TrimSpace(targetVer)
	if strings.ToLower(templateVer) == strings.ToLower(targetVer) {
		return 0
	}

	templateParts := reVersionParts.FindAllStringSubmatch(templateVer, -1)
	if len(templateParts) == 0 {
		return 1
	}
	targetParts := reVersionParts.FindAllStringSubmatch(targetVer, -1)
	if len(targetParts) == 0 {
		return -1
	}

	templateVersionParts := templateParts[0]
	targetVersionParts := targetParts[0]

	for i := 1; i < len(templateVersionParts); i++ {
		tplPart := templateVersionParts[i]
		tgtPart := targetVersionParts[i]

		if len(tplPart) == 0 && len(tgtPart) == 0 {
			continue
		}

		tplVal := 0
		tgtVal := 0
		isNum := true

		if len(tplPart) > 0 {
			v, err := strconv.Atoi(tplPart)
			if err != nil {
				isNum = false
			} else {
				tplVal = v
			}
		}

		if len(tgtPart) > 0 {
			v, err := strconv.Atoi(tgtPart)
			if err != nil {
				isNum = false
			} else {
				tgtVal = v
			}
		}

		if isNum {
			if i == 1 {
				// If major version is too far apart, declare as incompatible.
				diff := float64(tgtVal - tplVal)
				// Threshold at 1000 chosen as typically this is to avoid comparison of annual versions with
				// specific versions, e.g. 2014 against 14.x.
				if math.Abs(diff) > 1000 {
					return 2
				}
			}
			if tgtVal > tplVal {
				return 1
			} else if tplVal > tgtVal {
				return -1
			}
		} else {
			if tgtPart > tplPart {
				return 1
			} else if tplPart > tgtPart {
				return -1
			}
		}
	}

	return 0
}

func PatchCompare(templatePatch string, targetPatch string) int {
	if templatePatch == targetPatch {
		return 0
	}

	if templatePatch == "" {
		return 1 // If template empty, target > template.
	}

	// Use generic version compare function to compare the patch versions.
	return VersionCompare(templatePatch, targetPatch)
}

// VersionCompareProduct compares versions for a specific `product` from `vendor`.
// 2 is returned if the versions are not compatible/i.e. should not be matched.
func VersionCompareProduct(vendor, product, templateVer, targetVer string, templatePatch string, targetPatch string) int {
	var cmpVal int
	switch vendor {
	case "cisco":
		cmpVal = VersionCompareCisco(product, templateVer, targetVer)
	case "adobe":
		cmpVal = VersionCompareAdobe(product, templateVer, targetVer)
	case "juniper":
		cmpVal = VersionCompareJuniperJunos(templateVer, targetVer, templatePatch, targetPatch)
	default:
		cmpVal = VersionCompare(templateVer, targetVer)
		if cmpVal == 0 {
			return PatchCompare(templatePatch, targetPatch)
		}
	}
	return cmpVal
}

// ciscoIosVersion represents components of a Cisco IOS version.
type ciscoIosVersion struct {
	CodeName     string // e.g. denali, everest, fuji
	Major        string
	Minor        string
	Build        string
	InterimBuild string
	Train        string
	Rebuild      string
	SubRebuild   string
}

// Compare compares cisco version `v` against `another` and returns
// 1 if `v` > `another`, 0 if equal, -1 if `v` < `another`.
// 2 if the versions are incompatible, i.e. Major, Minor and Train are not identical.
func (v ciscoIosVersion) Compare(another ciscoIosVersion) int {
	if v.CodeName != another.CodeName || v.Major != another.Major || v.Minor != another.Minor || v.Train != another.Train {
		return 2 // incompatible versions for automatic comparison (would need inventory lists from Cisco).
	}

	vParts := []string{v.Major, v.Minor, v.Train, v.Build, v.InterimBuild, v.Rebuild, v.SubRebuild}
	anotherParts := []string{another.Major, another.Minor, another.Train, another.Build, another.InterimBuild, another.Rebuild, another.SubRebuild}

	for i := range vParts {
		vPart := vParts[i]
		anotherPart := anotherParts[i]

		if len(vParts) == 0 && len(anotherPart) == 0 {
			continue
		}

		vVal, anotherVal := 0, 0
		isNum := true

		if len(vPart) > 0 {
			v, err := strconv.Atoi(vPart)
			if err != nil {
				isNum = false
			} else {
				vVal = v
			}
		}

		if len(anotherPart) > 0 {
			v, err := strconv.Atoi(anotherPart)
			if err != nil {
				isNum = false
			} else {
				anotherVal = v
			}
		}

		if isNum {
			if vVal > anotherVal {
				return 1
			} else if vVal < anotherVal {
				return -1
			}
		} else {
			if vPart > anotherPart {
				return 1
			} else if vPart < anotherPart {
				return -1
			}
		}
	}

	return 0
}

// VersionCompareVendor compares versions for Cisco products.
// Currently has special handling for IOS and falls back to generic version handling otherwise.
func VersionCompareCisco(product, templateVer, targetVer string) int {
	switch product {
	case "ios":
		return VersionCompareCiscoIOS(templateVer, targetVer)
	case "adaptive_security_appliance_software":
		return VersionCompareCiscoASA(templateVer, targetVer)
	}

	return VersionCompare(templateVer, targetVer)
}

// Old fashioned IOS version: e.g. 9.5(1)201.
var reCiscoIOSVersion = regexp.MustCompile(`([\d]+)\.([\d]+)\(([\d]+)([a-zA-Z]+)?\)([a-zA-Z]+)?([\d]+)?([a-z])?`)

// Code named IOS version: e.g. denali-16.3.1
var reCiscoIOSCodenamedVersion = regexp.MustCompile(`([a-z]+)?-?([\d]+)\.([\d]+)\.([\d]+)`)

// VersionCompareCiscoIOS compares versions for Cisco IOS products.
// Currently has special handling for IOS and falls back to generic version handling otherwise.
//
// TODO(gunnsth): Comparing of Cisco IOS version is very error prone, as there are multiple version trains
// and it is not obvious what is new.  For example 15.0(2)SE12 is newer than 15.2(2a)E1.  Versions can
// only be compared within the same train.
// In addition there are code named versions such as: denali-16.2.2
func VersionCompareCiscoIOS(templateVer, targetVer string) int {
	var (
		verTpl ciscoIosVersion
		verTgt ciscoIosVersion
	)
	compatible := false

	// Check standard version string first.
	verPartsTpl := reCiscoIOSVersion.FindAllStringSubmatch(templateVer, -1)
	verPartsTgt := reCiscoIOSVersion.FindAllStringSubmatch(targetVer, -1)
	if len(verPartsTpl) == 1 && len(verPartsTpl[0]) == 8 && len(verPartsTgt) == 1 && len(verPartsTgt[0]) == 8 {
		compatible = true
		verTpl = ciscoIosVersion{
			Major:        verPartsTpl[0][1],
			Minor:        verPartsTpl[0][2],
			Build:        verPartsTpl[0][3],
			InterimBuild: verPartsTpl[0][4],
			Train:        verPartsTpl[0][5],
			Rebuild:      verPartsTpl[0][6],
			SubRebuild:   verPartsTpl[0][7],
		}
		verTgt = ciscoIosVersion{
			Major:        verPartsTgt[0][1],
			Minor:        verPartsTgt[0][2],
			Build:        verPartsTgt[0][3],
			InterimBuild: verPartsTgt[0][4],
			Train:        verPartsTgt[0][5],
			Rebuild:      verPartsTgt[0][6],
			SubRebuild:   verPartsTgt[0][7],
		}
	}

	if !compatible {
		// Fall back to check on codenamed version (e.g. denali-16.2.2).
		verPartsTpl = reCiscoIOSCodenamedVersion.FindAllStringSubmatch(templateVer, -1)
		verPartsTgt = reCiscoIOSCodenamedVersion.FindAllStringSubmatch(targetVer, -1)
		if len(verPartsTpl) == 1 && len(verPartsTpl[0]) == 5 && len(verPartsTgt) == 1 && len(verPartsTgt[0]) == 5 {
			compatible = true
			verTpl = ciscoIosVersion{
				CodeName: verPartsTpl[0][1],
				Major:    verPartsTpl[0][2],
				Minor:    verPartsTpl[0][3],
				Build:    verPartsTpl[0][4],
			}
			verTgt = ciscoIosVersion{
				CodeName: verPartsTgt[0][1],
				Major:    verPartsTgt[0][2],
				Minor:    verPartsTgt[0][3],
				Build:    verPartsTgt[0][4],
			}
			if verTpl.CodeName == "" {
				// If template does not have codename then ignore.
				verTgt.CodeName = ""
			}
		}
	}

	if !compatible {
		return 2 // Not compatible, cannot compare.
	}

	return verTgt.Compare(verTpl)
}

// CiscoASA Version Format 1: major(minor)build.
// Typically as reported directly from device.
// E.g. 9.5(1)201, 9.5(1) equivalent to 9.5.1.201, 9.5.1 respectively.
var reCiscoASAVersionFmt1 = regexp.MustCompile(`([\d\.]+)\(([\d\.]+)\)([\d]+)?`)

// CiscoASA Version Format 2: major.minor / a.b.c.d.
// E.g. 9.5.1.201, 9.5.1.
// Sometimes used by Cisco and NVD vulnerability reports.
var reCiscoASAVersionFmt2 = regexp.MustCompile(`([\d]+\.[\d]+)\.([\d]+\.?[\d]*)`)

// ciscoASAVersion represents components of a Cisco ASA version.
// For instance, if the ASA version is 8.4(2.3)49, then asa_release is 8.4(2.3)49,
// asa_major_release is 8.4, asa_minor_release is 2.3 and asa_build is 49.
type ciscoASAVersion struct {
	Major string
	Minor string
	Build string
}

// Compare compares cisco version `v` against `another` and returns
// 1 if `v` > `another`, 0 if equal, -1 if `v` < `another`.
func (v *ciscoASAVersion) Compare(another *ciscoASAVersion) int {
	vParts := []string{v.Major, v.Minor, v.Build}
	anotherParts := []string{another.Major, another.Minor, another.Build}

	for i := range vParts {
		vPart := vParts[i]
		anotherPart := anotherParts[i]

		if len(vPart) == 0 && len(anotherPart) == 0 {
			continue
		}

		cmpVal := VersionCompare(anotherPart, vPart)
		if cmpVal != 0 {
			return cmpVal
		}
	}

	return 0
}

// parsCiscoASAVersion parses Cisco ASA version information from string `verstr` and returns a ciscoASAVersion.
// The returned bool flag is true if there was a match.
func parseCiscoASAVersion(verstr string) (*ciscoASAVersion, bool) {
	// Try format 1 first.
	parts := reCiscoASAVersionFmt1.FindAllStringSubmatch(verstr, -1)
	if len(parts) > 0 && len(parts[0]) == 4 {
		ver := &ciscoASAVersion{
			Major: parts[0][1],
			Minor: parts[0][2],
			Build: parts[0][3],
		}
		return ver, true
	}

	// Try format 2, otherwise not a match.
	parts = reCiscoASAVersionFmt2.FindAllStringSubmatch(verstr, -1)
	if len(parts) > 0 && len(parts[0]) == 3 {
		ver := &ciscoASAVersion{
			Major: parts[0][1],
			Minor: parts[0][2],
		}
		return ver, true
	}

	return nil, false
}

// VersionCompareCiscoASA compares versions for Cisco ASA products.
// Currently has special handling for IOS and falls back to generic version handling otherwise.
func VersionCompareCiscoASA(templateVer, targetVer string) int {
	verTpl, match := parseCiscoASAVersion(templateVer)
	if !match {
		return VersionCompare(templateVer, targetVer)
	}

	verTgt, match := parseCiscoASAVersion(targetVer)
	if !match {
		return VersionCompare(templateVer, targetVer)
	}

	return verTgt.Compare(verTpl)
}

var (
	reAdobeVersion = regexp.MustCompile(`(\d{1,4})\.(\d{1,3})\.(\d{2,5})`)
)

// VersionCompareAdobe compares versions for Adobe products.
// Currently has special handling for certain products and falls back to generic version handling otherwise.
func VersionCompareAdobe(product, templateVer, targetVer string) int {
	if !strings.HasPrefix(product, "acrobat") {
		return VersionCompare(templateVer, targetVer)
	}

	partsTpl := reAdobeVersion.FindAllStringSubmatch(templateVer, -1)
	partsTgt := reAdobeVersion.FindAllStringSubmatch(targetVer, -1)
	if len(partsTpl) == 0 || len(partsTpl[0]) != 4 || len(partsTgt) == 0 || len(partsTgt[0]) != 4 {
		return VersionCompare(templateVer, targetVer)
	}

	verPartsTpl := partsTpl[0][1:]
	verPartsTgt := partsTgt[0][1:]

	majorTpl, err := strconv.Atoi(verPartsTpl[0])
	if err != nil {
		return VersionCompare(templateVer, targetVer)
	}
	majorTgt, err := strconv.Atoi(verPartsTgt[0])
	if err != nil {
		return VersionCompare(templateVer, targetVer)
	}

	verTpl := verPartsTpl[0] + "." + verPartsTpl[1] + "." + verPartsTpl[2]
	verTgt := verPartsTgt[0] + "." + verPartsTgt[1] + "." + verPartsTgt[2]

	if len(verTpl) == 12 && majorTpl >= 15 && majorTpl < 100 {
		verTpl = "20" + verTpl
	}
	if len(verTgt) == 12 && majorTgt >= 15 && majorTgt < 100 {
		verTgt = "20" + verTgt
	}

	if (len(verTpl) == 14 || len(verTgt) == 14) && len(verTpl) != len(verTgt) {
		// Incompatible versions.
		return 2
	}

	return VersionCompare(verTpl, verTgt)
}

// junosVersion represents the version format of Juniper Junos firmware.
// E.g. 12.2R6.1 or 12.1X44-D10.4
type junosVersion struct {
	Major              string // e.g. for 12.2R6.1 would be '12'
	Minor              string // e.g. for 12.2R6.1 would be '2'
	Type               string // e.g. for 12.2R6.1 is 'R' (R: normal/I: internal/F: feature/S: service/B: beta/X: exception)
	Build              string // e.g. for 12.2R6.1 is '6', for 12.1X44-D10.4 is '44'
	MaintenanceRelease string // e.g. for 14.2R3-S4.5 is '4', for 10.4S4.2 does not exist (''), for 12.1X44-D10.4 is 'D10'
	Spin               string // e.g. for 12.2R6.1 is '1', for 12.1X44-D10.4 is '4'
}

var reJunosVersion = regexp.MustCompile(`([\d]+)\.([\d+])([a-zA-Z]+)([\d]+)\-?([a-zA-Z][\d]+)?\.?([\d+])?`)

func ParseJunosVersion(raw string) (ver junosVersion, found bool) {
	raw = strings.ToUpper(raw)

	parts := reJunosVersion.FindAllStringSubmatch(raw, -1)
	if len(parts) != 1 || len(parts[0]) != 7 {
		return ver, false
	}

	return junosVersion{
		Major:              parts[0][1],
		Minor:              parts[0][2],
		Type:               parts[0][3],
		Build:              parts[0][4],
		MaintenanceRelease: parts[0][5],
		Spin:               parts[0][6],
	}, true
}

// Compare compares Junos version `v` against `another` and returns
// 1 if `v` > `another`, 0 if equal, -1 if `v` < `another`.
// 2 if the versions are incompatible, i.e. Major, Minor and Train are not identical.
func (v junosVersion) Compare(another junosVersion) int {
	// Requires major, minor, type and build to be equal, otherwise incompatiable.
	// e.g. 15.1X48-D160 and 15.1X49-D20 are incompatible, whereas
	// 15.1X49-D10 < 15.1X49-D160.
	// Too strict? Otherwise can lead to false positives.  Typically for Juniper Junos there should
	// be one entry for each build specifying the lowest patch that is vulnerable.
	if v.Major != another.Major || v.Minor != another.Minor || v.Type != another.Type || v.Build != another.Build {
		return 2 // incompatible versions for automatic comparison
	}

	// Split D160 into "D" "160"
	vPatchType := ""
	vPatchRest := ""
	if len(v.MaintenanceRelease) > 0 {
		vPatchType = string(v.MaintenanceRelease[0])
		vPatchRest = v.MaintenanceRelease[1:]
	}
	anotherPatchType := ""
	anotherPatchRest := ""
	if len(another.MaintenanceRelease) > 0 {
		anotherPatchType = string(another.MaintenanceRelease[0])
		anotherPatchRest = another.MaintenanceRelease[1:]
	}

	vParts := []string{v.Major, v.Minor, v.Type, v.Build, vPatchType, vPatchRest, v.Spin}
	anotherParts := []string{another.Major, another.Minor, another.Type, another.Build, anotherPatchType, anotherPatchRest, another.Spin}

	for i := range vParts {
		vPart := vParts[i]
		anotherPart := anotherParts[i]

		if len(vParts) == 0 && len(anotherPart) == 0 {
			continue
		}

		vVal, anotherVal := 0, 0
		isNum := true

		if len(vPart) > 0 {
			v, err := strconv.Atoi(vPart)
			if err != nil {
				isNum = false
			} else {
				vVal = v
			}
		}

		if len(anotherPart) > 0 {
			v, err := strconv.Atoi(anotherPart)
			if err != nil {
				isNum = false
			} else {
				anotherVal = v
			}
		}

		if isNum {
			if vVal > anotherVal {
				return 1
			} else if vVal < anotherVal {
				return -1
			}
		} else {
			if vPart > anotherPart {
				return 1
			} else if vPart < anotherPart {
				return -1
			}
		}
	}

	return 0
}

// VersionCompareJuniperJunos compares versions for Juniper Junos products.
func VersionCompareJuniperJunos(templateVer, targetVer, templatePatch, targetPatch string) int {
	templateVer = strings.ToUpper(templateVer)
	templatePatch = strings.ToUpper(templatePatch)
	targetVer = strings.ToUpper(targetVer)
	targetPatch = strings.ToUpper(targetPatch)
	tplVer, tplMatch := ParseJunosVersion(templateVer)
	tgtVer, tgtMatch := ParseJunosVersion(targetVer)

	if len(tplVer.MaintenanceRelease) == 0 {
		tplVer.MaintenanceRelease = templatePatch
	}
	if len(tgtVer.MaintenanceRelease) == 0 {
		tgtVer.MaintenanceRelease = targetPatch
	}

	compatible := false
	if tplMatch && tgtMatch {
		compatible = true
	}

	if !compatible {
		return 2 // Not compatible, cannot compare.
	}

	return tgtVer.Compare(tplVer)
}
