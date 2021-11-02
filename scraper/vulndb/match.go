package vulndb

import (
	"regexp"
	"sort"
	"strings"

	"nanscraper/common"
)

// GetAdvisory looks up NVD advisory by `cve`.
func GetAdvisory(session *VulnDBSession, cve string) (*NVDCVEAdvisory, error) {
	var advisory NVDCVEAdvisory
	has, err := session.Where(`LOWER(cve_id) = LOWER(?)`, cve).Get(&advisory)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	}
	return &advisory, nil
}

// GetVendor looks up appropriate VulndbVendor for input `vendorName`.
// Uses MatchVendor which returns more detailed information about the match.
func GetVendor(session *VulnDBSession, vendorName string) (*VulndbVendor, error) {
	match, err := MatchVendor(session, vendorName)
	if err != nil {
		return nil, err
	}
	if match == nil {
		return nil, nil
	}

	return match.Vendor, nil
}

type VendorMatchResult struct {
	Vendor           *VulndbVendor
	FromAlias        bool
	VendorAlias      string // if matched by alias.
	CPEFriendlyMatch bool
	CPEFriendlyName  string // if matched via cpe friendly name.
}

// MatchVendor looks up appropriate VulndbVendor for input `vendorName`, following the process:
// 1. Look for vendor by `vendorName` in vulndb_vendors.
// 2. If exact match, return it.
// 3. Look for vendor alias by `vendorName` in vulndb_vendor_aliases.
// 4. If match, load corresponding record from vulndb_vendors and return.
// 5. Make lowercase and strip out text such as " corporation", " incorporated", etc. and look for vendor by
//    the prepared name, returning only on exact match.
// 6. Otherwise return nil to indicate there was no match.
func MatchVendor(session *VulnDBSession, vendorName string) (*VendorMatchResult, error) {
	var result VendorMatchResult

	// Step 1.
	var vendor VulndbVendor
	has, err := session.Where(`name = ?`, vendorName).Get(&vendor)
	if err != nil {
		return nil, err
	}
	// Step 2.
	if has {
		result.Vendor = &vendor
		return &result, nil
	}
	// Step 3.
	var vendorAlias VulndbVendorAlias
	has, err = session.Where(`alias = ?`, vendorName).Get(&vendorAlias)
	if err != nil {
		return nil, err
	}
	// Step 4.
	if has {
		_, err = session.Where(`id = ?`, vendorAlias.VendorID).Get(&vendor)
		if err != nil {
			return nil, err
		}
		result.Vendor = &vendor
		result.FromAlias = true
		result.VendorAlias = vendorAlias.Alias
		return &result, nil
	}
	// Step 5.
	cpeFriendly := prepVendorName(vendorName)
	has, err = session.Where(`name = ?`, cpeFriendly).Get(&vendor)
	if err != nil {
		return nil, err
	}
	if has {
		result.Vendor = &vendor
		result.CPEFriendlyMatch = true
		result.CPEFriendlyName = cpeFriendly
		return &result, nil
	}

	// Step 6.
	return nil, nil
}

// Number of hits per CVE match for product. Ordered by CVSS3 base score.
const maxNumHits = 5

// CVEMatch is a result from MatchCVEs containing a match to an advisory and information about the match.
type CVEMatch struct {
	Advisory   NVDCVEAdvisory
	TargetedSW bool // True if match was specific to the target_sw.
}

// MatchCVEs looks up a product by systype ("o"/"a"), publisher, title, version, patch, target_sw and returns a list of CVE ids.
// 1. Look up vendor/product directly by vendor/product aliases and populate productIDs with match.
// 2. If no matches. Look up vendor (both directly, checking vendor aliases, and potential cpe-friendly fits).
// 2b. If no vendor match - return nil.
// 3. If vendor match, look for matching product under vendor name, and populate the product ids into productIDs.
// 3b. If no product ID matches, return nil.
// 4. For each productID check all the product items for matching version.
// 5. For each product item, look up CVEs and populate a list of CVEs.
// 6. Return the alphabetically sorted list of CVE advisories.
// Returns up to `maxNumHits` advisories ordered by CVSS3 base score.
func MatchCVEs(session *VulnDBSession, systype, publisher, title, version, patch, target_sw string) ([]CVEMatch, error) {
	cacheKey := systype + publisher + title + version + patch + target_sw
	if cachedResult, cached := session.cached[cacheKey]; cached {
		return cachedResult, nil
	}

	var productIDs []int64

	// Step 1.
	var prodalias vulndbProductAlias
	has, err := session.Where("vendor_alias = ? AND ? GLOB product_alias", publisher, title).Get(&prodalias)
	if err != nil {
		return nil, err
	}
	if has {
		productIDs = append(productIDs, prodalias.ProductID)
	}

	if len(productIDs) < 1 {
		// Step 2.
		vendor, err := GetVendor(session, publisher)
		if err != nil {
			log.Debugf("ERROR getting vendor: %v", err)
			return nil, err
		}
		if vendor == nil {
			// Step 2b.
			return nil, err
		}

		// Step 3.
		// Try both title directly, and prepared cpe-friendly product name.
		cpeFriendly := prepProductName(title, vendor.Name)
		candidates := []string{title}
		candidates = append(candidates, alternativeNames(cpeFriendly)...)
		var products []vulndbProduct

		whereSQL := "vendor_id = ? AND " + common.MakeInSql("product_name", len(candidates))
		params := []interface{}{vendor.ID}
		for _, candidate := range candidates {
			params = append(params, candidate)
		}
		err = session.Where(whereSQL, params...).Find(&products)
		if err != nil {
			return nil, err
		}
		for _, product := range products {
			productIDs = append(productIDs, product.ID)
		}
	}

	// Step 3b.
	if len(productIDs) < 1 {
		return nil, nil
	}

	// Step 4 (version matching).
	// First pulls all the potential matches by productID and filters out product items by version (in go code).
	var productItems []vulndbProductItem
	whereSQL := common.MakeInSql("product_id", len(productIDs)) + " AND LOWER(systype) = LOWER(?)"
	var params []interface{}
	for _, productID := range productIDs {
		params = append(params, productID)
	}
	params = append(params, systype)
	err = session.Where(whereSQL, params...).Find(&productItems)
	if err != nil {
		return nil, err
	}
	var productItemIDs []int64
	specificMatches := map[int64]bool{} // Map of SW Target specific matches.
	// Filter by version.
	for _, item := range productItems {
		specific := false
		if item.SWTarget != nil && len(*item.SWTarget) > 0 {
			if !matchSWTarget(*item.SWTarget, target_sw) {
				continue
			}
			specific = true
		}

		product, err := session.GetProductById(item.ProductID)
		if err != nil {
			log.Debugf("ERROR: %v", err)
			return nil, err
		}
		if product == nil {
			log.Debugf("ERROR: Product ID missing - skipping")
			continue
		}

		vendor, err := session.GetVendorById(product.VendorID)
		if err != nil {
			log.Debugf("ERROR: %v", err)
			return nil, err
		}
		if vendor == nil {
			log.Debugf("ERROR: Product ID missing - skipping")
			continue
		}

		// Check if is ignored?
		var ignoreItem []vulndbIgnoreListItem
		err = session.Where(`vendor_name = ? AND ? GLOB product_name_glob`, vendor.Name, product.ProductName).Find(&ignoreItem)
		if err != nil {
			return nil, err
		}
		if len(ignoreItem) > 0 {
			// Ignore the item.
			continue
		}

		matches := false
		if item.Version != nil && len(*item.Version) > 0 && *item.Version != "*" {
			if VersionCompareProduct(vendor.Name, product.ProductName, *item.Version, version, item.Patch, patch) == 0 {
				matches = true
			}
		} else {
			hasStartRange := false
			hasEndRange := false
			startRangeMatch := true
			endRangeMatch := true
			if item.VersionStartIncluding != nil {
				hasStartRange = true
				cmpVal := VersionCompareProduct(vendor.Name, product.ProductName, *item.VersionStartIncluding, version, item.Patch, patch)
				if cmpVal == -1 || cmpVal == 2 { // version < startIncluding
					startRangeMatch = false
				}
			} else if item.VersionStartExcluding != nil {
				hasStartRange = true
				startRangeMatch = true
				cmpVal := VersionCompareProduct(vendor.Name, product.ProductName, *item.VersionStartExcluding, version, item.Patch, patch)
				if cmpVal == 0 || cmpVal == -1 || cmpVal == 2 { // version <= startExcluding
					startRangeMatch = false
				}
			}
			if item.VersionEndIncluding != nil {
				hasEndRange = true
				cmpVal := VersionCompareProduct(vendor.Name, product.ProductName, *item.VersionEndIncluding, version, item.Patch, patch)
				if cmpVal == 1 || cmpVal == 2 { // version > endExcluding
					endRangeMatch = false
				}
			} else if item.VersionEndExcluding != nil {
				hasEndRange = true
				cmpVal := VersionCompareProduct(vendor.Name, product.ProductName, *item.VersionEndExcluding, version, item.Patch, patch)
				if cmpVal == 0 || cmpVal == 1 || cmpVal == 2 { // version >= endExcluding
					endRangeMatch = false
				}
			}
			if (!hasStartRange || startRangeMatch) && hasEndRange && endRangeMatch {
				matches = true
			}
		}

		if matches {
			productItemIDs = append(productItemIDs, item.ID)
			if specific {
				specificMatches[item.ID] = true
			}
		}
	}
	if len(productItemIDs) == 0 {
		return nil, nil
	}

	// Step 5.
	var vulns []vulndbVulnerability
	whereSQL = common.MakeInSql("product_item_id", len(productItemIDs))
	params = []interface{}{}
	for _, id := range productItemIDs {
		params = append(params, id)
	}
	err = session.Where(whereSQL, params...).Find(&vulns)
	if err != nil {
		return nil, err
	}
	if len(vulns) == 0 {
		return nil, nil
	}
	var advisoryIDs []int64
	specificCVEMatches := map[int64]bool{}
	for _, vuln := range vulns {
		advisoryIDs = append(advisoryIDs, vuln.AdvisoryID)
		if _, specificMatch := specificMatches[vuln.ProductItemID]; specificMatch {
			specificCVEMatches[vuln.AdvisoryID] = true
		}
	}

	var advisories []NVDCVEAdvisory
	err = common.ProcessChunks(advisoryIDs, 900, func(start, end int) error {
		// Redefine locally for each chunk to process.
		advisoryIDs := advisoryIDs[start:end]
		whereSQL := common.MakeInSql("id", len(advisoryIDs))
		params := []interface{}{}
		for _, id := range advisoryIDs {
			params = append(params, id)
		}

		var advisoriesChunk []NVDCVEAdvisory
		err = session.Where(whereSQL, params...).OrderBy(`cvss3_base_score DESC`).Find(&advisoriesChunk)
		if err != nil {
			return err
		}
		if len(advisoriesChunk) > maxNumHits {
			advisoriesChunk = advisoriesChunk[0:maxNumHits]
		}
		advisories = append(advisories, advisoriesChunk...)
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Sort by importance and limit to maxNumHits.
	if len(advisories) > maxNumHits {
		// Sort by base score, descending.
		sort.SliceStable(advisories, func(i, j int) bool {
			cvss3i := 0.0
			cvss3j := 0.0
			if advisories[i].CVSS3BaseScore != nil {
				cvss3i = *advisories[i].CVSS3BaseScore
			}
			if advisories[j].CVSS3BaseScore != nil {
				cvss3j = *advisories[j].CVSS3BaseScore
			}

			return cvss3i >= cvss3j
		})
		advisories = advisories[0:maxNumHits]
	}

	// Step 6.
	sort.Slice(advisories, func(i, j int) bool {
		return advisories[i].CVEID < advisories[j].CVEID
	})

	matches := make([]CVEMatch, 0, len(advisories))
	for _, advisory := range advisories {
		_, isSpecific := specificCVEMatches[advisory.Id]
		match := CVEMatch{
			Advisory:   advisory,
			TargetedSW: isSpecific,
		}
		matches = append(matches, match)
	}

	session.cached[cacheKey] = matches
	return matches, nil
}

func normalizeSWTarget(swTarget string) string {
	swTarget = strings.ToLower(swTarget)

	// NOTE: This mapping should possibly be defined in vulndb in the future so its easy to maintain.
	switch swTarget {
	case "mac", "mac_os", "mac_os_x":
		return "mac_os_x"
	case "ios", "ipad", "iphone_os", "ipod_touch":
		return "ios"
	}

	return swTarget
}

// matchSWTarget matches template sw_target against actual. The sw_target (part of CPE) is sometimes
// used to indicate that a vulnerability only applies to a certain OS/platform.
// Example VLC vulnerability only on IOS devices (sw_target=ios).  The sw_target is only a single
// name (not vendor) and may not always be the same as the CPE product name for that software.
// There may also be multiple sw_targets for a certain product, example: mac_os, mac_os_x.
// Thus need to normalize those names to ensure consistency.
func matchSWTarget(tplTarget, target string) bool {
	if len(tplTarget) < 2 {
		// Always a match if not specified in the template.
		// NOTE: Not a match if template is specified but target empty.
		return true
	}

	tplTarget = normalizeSWTarget(tplTarget)
	target = normalizeSWTarget(target)

	return strings.ToLower(tplTarget) == strings.ToLower(target)
}

// prepVendorName prepares CPE friendly vendor name from input title, making lowercase and stripping out parts.
func prepVendorName(vendorTitle string) string {
	target := strings.ToLower(vendorTitle)
	target = strings.Replace(target, " corporation", "", 1)
	target = strings.Replace(target, " incorporated", "", 1)
	target = strings.Replace(target, " systems", "", 1)
	target = strings.Replace(target, " inc.", "", 1)
	target = strings.Replace(target, " corp.", "", 1)
	target = strings.Replace(target, " s.r.o.", "", 1)
	target = strings.Replace(target, " s.a.r.l.", "", 1)
	target = strings.Replace(target, " e.h.f.", "", 1)
	target = strings.Replace(target, ".com", "", 1)
	target = strings.Replace(target, ".org", "", 1)
	target = strings.Replace(target, "http://", "", 1)
	target = strings.Replace(target, "https://", "", 1)
	target = strings.Replace(target, ",", "", -1)
	target = strings.Replace(target, ".", "", -1)
	target = strings.Replace(target, " ", "_", -1)
	target = strings.TrimSpace(target)

	return target
}

var (
	reVersion     = regexp.MustCompile(`(\s|version\s|v)?\s?([\d]+\.[\d]+(\.[\d]+)?(\.[\d]+)?)(-[^\s]+)?`)
	reBracketed   = regexp.MustCompile(`\([^\)]+\)`)
	reMultispaces = regexp.MustCompile(`\s\s+`)
	reIsNumeric   = regexp.MustCompile(`^\d+$`)
)

// prepProductName normalized product string, making lowercase, stripping vendor name, version strings and text within
// parenthesis, returns a CPE friendly product name.
// Spaces converted to underscore: " " to "_".
func prepProductName(title string, vendor string) string {
	title = strings.ToLower(title)
	vendor = strings.ToLower(vendor)

	title = reMultispaces.ReplaceAllString(title, " ")
	title = reVersion.ReplaceAllString(title, "")
	title = strings.Replace(title, "-", " ", -1)
	title = strings.Replace(title, "–", " ", -1)
	// Strip vendor name.
	if strings.Contains(title, vendor) {
		bak := strings.TrimSpace(title)
		title = strings.Replace(title, " "+vendor+" ", "", 1)
		title = strings.Replace(title, vendor+" ", "", 1)
		if len(vendor) > 3 {
			title = strings.Replace(title, vendor, "", 1)
		}

		title = strings.TrimSpace(title)
		if len(title) == 0 || reIsNumeric.MatchString(title) {
			// Edge case when product name is the same as vendor name which is actually pretty common.
			title = bak
		}
	}

	title = reBracketed.ReplaceAllString(title, "")
	title = strings.Replace(title, "  ", " ", -1)
	title = strings.TrimSpace(title)
	title = strings.Replace(title, " ", "_", -1)

	return title
}

var (
	reYear = regexp.MustCompile(`[-_]*[1-2]\d\d\d[-_]*`)
)

func alternativeNames(name string) []string {
	var names []string

	names = append(names, name)
	nameb := []byte(name)
	for i, b := range nameb {
		switch b {
		case '-':
			nameb[i] = '_'
			names = append(names, string(nameb))
		case '_':
			nameb[i] = '-'
			names = append(names, string(nameb))
		}
	}

	// Remove years.
	for _, n := range names {
		n2 := reYear.ReplaceAllString(n, "")
		if n != n2 {
			n2 = strings.TrimSpace(n2)
			names = append(names, n2)
		}
	}

	return names
}
