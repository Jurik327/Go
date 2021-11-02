package vulndb

import (
	"compress/gzip"
	"encoding/json"
	"os"
	"time"

	"nanscraper/vulndb/nvdjson"
)

// Loads a gzipped (compressed) NVD CVE JSON input file contents.
func loadNVDCVEJSON(inputPath string, minCVSSScore float64) (*CVEDirectory, error) {
	f, err := os.Open(inputPath)
	if err != nil {
		return nil, err
	}

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}

	var cveDict nvdjson.NVD

	decoder := json.NewDecoder(gzReader)
	err = decoder.Decode(&cveDict)
	if err != nil {
		return nil, err
	}

	// Map of advisories for each system type.
	cveDir := &CVEDirectory{}
	cveDir.Map = map[string]map[string]map[string][]cveDirEntry{}
	cveDir.Map["a"] = map[string]map[string][]cveDirEntry{}
	cveDir.Map["o"] = map[string]map[string][]cveDirEntry{}
	cveDir.Map["h"] = map[string]map[string][]cveDirEntry{}

	cveDir.Advisories = []CVEAdvisory{}

	log.Debugf("CVE dict with %d items", len(cveDict.CVEItems))
	for _, item := range cveDict.CVEItems {
		advisory := CVEAdvisory{}
		advisory.CVEID = item.CVE.Meta.ID
		advisory.Summary = item.CVE.GetDescription()

		timeLayout := "2006-01-02T15:04Z"
		pubDate, err := time.Parse(timeLayout, item.PublishedDate)
		if err != nil {
			log.Debugf("ERROR: Unable to parse pub date: %v", err)
			continue
		}
		advisory.PublishedAtInt = pubDate.Unix()

		mDate, err := time.Parse(timeLayout, item.LastModifiedDate)
		if err != nil {
			log.Debugf("ERROR: Unable to parse mod date: %v", err)
			continue
		}
		advisory.LastModifiedAtInt = mDate.Unix()

		for _, ref := range item.References() {
			if ref.IsVendor() {
				if len(ref.URL) > 0 {
					advisory.VendorRefURL = ref.URL
				}
				if ref.RefSource == "CONFIRM" {
					val := true
					advisory.ReportConfirmed = &val
				}
			}
			if ref.HasTag("Patch") {
				val := true
				advisory.HasPatch = &val
			}
		}

		// TODO: Parse from CVSS "vectorString".
		// CVSS2.
		if item.Impact.BaseMetricV2 != nil {
			cvss2 := item.Impact.BaseMetricV2.CVSSV2
			advisory.CVSS2 = &CVECVSS2{}

			advisory.CVSS2.BaseScore = cvss2.BaseScore

			switch cvss2.AccessVector {
			case "LOCAL":
				val := CVSSAccessVectorLocal
				advisory.CVSS2.AccessVector = &val
			case "NETWORK":
				val := CVSSAccessVectorNetwork
				advisory.CVSS2.AccessVector = &val
			case "ADJACENT_NETWORK":
				val := CVSSAccessVectorAdjacentNetwork
				advisory.CVSS2.AccessVector = &val
			default:
				log.Debugf("ERROR - unsupported access vector: '%s' - ignoring", cvss2.AccessVector)
			}

			switch cvss2.AccessComplexity {
			case "LOW":
				val := CVSSAccessComplexityLow
				advisory.CVSS2.AccessComplexity = &val
			case "MEDIUM":
				val := CVSSAccessComplexityMedium
				advisory.CVSS2.AccessComplexity = &val
			case "HIGH":
				val := CVSSAccessComplexityHigh
				advisory.CVSS2.AccessComplexity = &val
			default:
				log.Debugf("ERROR: Unsupported access complexity: '%s' - ignoring", cvss2.AccessComplexity)
			}
			switch cvss2.Authentication {
			case "NONE":
				val := CVSSAuthenticationNone
				advisory.CVSS2.Authentication = &val
			case "SINGLE_INSTANCE", "SINGLE":
				val := CVSSAuthenticationSingleInstance
				advisory.CVSS2.Authentication = &val
			case "MULTIPLE_INSTANCES", "MULTIPLE":
				val := CVSSAuthenticationMultipleInstances
				advisory.CVSS2.Authentication = &val
			default:
				log.Debugf("ERROR: Unsupported authentication: '%s' - ignoring", cvss2.Authentication)
			}

			switch cvss2.ConfidentialityImpact {
			case "NONE":
				val := CVSSConfidentialityImpactNone
				advisory.CVSS2.ConfidentialityImpact = &val
			case "PARTIAL":
				val := CVSSConfidentialityImpactPartial
				advisory.CVSS2.ConfidentialityImpact = &val
			case "COMPLETE":
				val := CVSSConfidentialityImpactComplete
				advisory.CVSS2.ConfidentialityImpact = &val
			default:
				log.Debugf("ERROR: Unsupported confidentiality impact: '%s' - ignoring", cvss2.ConfidentialityImpact)
			}
		}

		if item.Impact.BaseMetricV3 != nil {
			cvss3 := item.Impact.BaseMetricV3.CVSSV3
			advisory.CVSS3 = &CVECVSS3{}

			switch cvss3.AttackComplexity {
			case "HIGH":
				val := AttackComplexityTypeHigh
				advisory.CVSS3.AttackComplexity = &val
			case "LOW":
				val := AttackComplexityTypeLow
				advisory.CVSS3.AttackComplexity = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 attack complexity: '%s' - ignoring", cvss3.AttackComplexity)
			}

			switch cvss3.AttackVector {
			case "NETWORK":
				val := AttackVectorTypeNetwork
				advisory.CVSS3.AttackVector = &val
			case "ADJACENT_NETWORK":
				val := AttackVectorTypeAdjacentNetwork
				advisory.CVSS3.AttackVector = &val
			case "LOCAL":
				val := AttackVectorTypeLocal
				advisory.CVSS3.AttackVector = &val
			case "PHYSICAL":
				val := AttackVectorTypePhysical
				advisory.CVSS3.AttackVector = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 attack vector: '%s' - ignoring", cvss3.AttackVector)
			}

			switch cvss3.AvailabilityImpact {
			case "NONE":
				val := CiaTypeNone
				advisory.CVSS3.AvailabilityImpact = &val
			case "LOW":
				val := CiaTypeLow
				advisory.CVSS3.AvailabilityImpact = &val
			case "HIGH":
				val := CiaTypeHigh
				advisory.CVSS3.AvailabilityImpact = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 availability impact: '%s' - ignoring", cvss3.AttackVector)
			}

			advisory.CVSS3.BaseScore = cvss3.BaseScore

			switch cvss3.BaseSeverity {
			case "NONE":
				val := SeverityTypeNone
				advisory.CVSS3.BaseSeverity = val
			case "LOW":
				val := SeverityTypeLow
				advisory.CVSS3.BaseSeverity = val
			case "MEDIUM":
				val := SeverityTypeMedium
				advisory.CVSS3.BaseSeverity = val
			case "HIGH":
				val := SeverityTypeHigh
				advisory.CVSS3.BaseSeverity = val
			case "CRITICAL":
				val := SeverityTypeCritical
				advisory.CVSS3.BaseSeverity = val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 base severity: '%s' - ignoring", cvss3.BaseSeverity)
			}

			switch cvss3.ConfidentialityImpact {
			case "NONE":
				val := CiaTypeNone
				advisory.CVSS3.ConfidentialityImpact = &val
			case "LOW":
				val := CiaTypeLow
				advisory.CVSS3.ConfidentialityImpact = &val
			case "HIGH":
				val := CiaTypeHigh
				advisory.CVSS3.ConfidentialityImpact = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 confidentiality impact: '%s' - ignoring", cvss3.ConfidentialityImpact)
			}

			switch cvss3.IntegrityImpact {
			case "NONE":
				val := CiaTypeNone
				advisory.CVSS3.IntegrityImpact = &val
			case "LOW":
				val := CiaTypeLow
				advisory.CVSS3.IntegrityImpact = &val
			case "HIGH":
				val := CiaTypeHigh
				advisory.CVSS3.IntegrityImpact = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 integrity impact: '%s' - ignoring", cvss3.IntegrityImpact)
			}

			switch cvss3.PrivilegesRequired {
			case "HIGH":
				val := PrivilegesRequiredTypeHigh
				advisory.CVSS3.PrivilegesRequired = &val
			case "LOW":
				val := PrivilegesRequiredTypeLow
				advisory.CVSS3.PrivilegesRequired = &val
			case "NONE":
				val := PrivilegesRequiredTypeNone
				advisory.CVSS3.PrivilegesRequired = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 privileges required: '%s' - ignoring", cvss3.PrivilegesRequired)
			}

			switch cvss3.Scope {
			case "UNCHANGED":
				val := ScopeTypeUnchanged
				advisory.CVSS3.Scope = &val
			case "CHANGED":
				val := ScopeTypeChanged
				advisory.CVSS3.Scope = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 scope: '%s' - ignoring", cvss3.Scope)
			}

			switch cvss3.UserInteraction {
			case "NONE":
				val := UserInteractionTypeNone
				advisory.CVSS3.UserInteraction = &val
			case "REQUIRED":
				val := UserInteractionTypeRequired
				advisory.CVSS3.UserInteraction = &val
			default:
				log.Debugf("ERROR: Unsupported CVSS3 user interaction: '%s' - ignoring", cvss3.UserInteraction)
			}

			advisory.CVSS3.VectorString = cvss3.VectorString
		}

		cveDir.Advisories = append(cveDir.Advisories, advisory)

		vulnItems, err := item.VulnerableCPEs()
		if err != nil {
			return nil, err
		}

		for _, vulnItem := range vulnItems {
			cpeParts, err := ParseCPE(vulnItem.CPE23)
			if err != nil {
				return nil, err
			}

			systype := cpeParts.Systype
			vendor := cpeParts.Vendor
			product := cpeParts.Product

			if len(vendor) < 1 || len(product) < 1 {
				continue
			}

			_, has := cveDir.Map[systype][vendor]
			if !has {
				cveDir.Map[systype][vendor] = map[string][]cveDirEntry{}
			}

			_, has = cveDir.Map[systype][vendor][product]
			if !has {
				cveDir.Map[systype][vendor][product] = []cveDirEntry{}
			}

			var version *string
			if len(cpeParts.Version) > 0 {
				v := cpeParts.Version
				version = &v
			}
			entry := cveDirEntry{
				CVEID:                 item.CVE.Meta.ID,
				Version:               version,
				VersionStartExcluding: vulnItem.VersionStartExcluding,
				VersionStartIncluding: vulnItem.VersionStartIncluding,
				VersionEndExcluding:   vulnItem.VersionEndExcluding,
				VersionEndIncluding:   vulnItem.VersionEndIncluding,
				Update:                cpeParts.Patch,
				Arch:                  cpeParts.Edition,
				SWTarget:              cpeParts.TargetSW,
				RawCPE23:              vulnItem.CPE23,
			}

			cveDir.Map[systype][vendor][product] = append(cveDir.Map[systype][vendor][product], entry)
		}
	}

	log.Debugf("CVE Directory with %d hardware vendors", len(cveDir.Map["h"]))
	log.Debugf("CVE Directory with %d OS vendors", len(cveDir.Map["o"]))
	log.Debugf("CVE Directory with %d application vendors", len(cveDir.Map["a"]))
	return cveDir, nil
}
