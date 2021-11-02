package vulndb

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"xorm.io/xorm"

	"github.com/gocolly/colly/v2"

	"nanscraper/pkg/models/msrcapi"
)

type CreateDBParams struct {
	VulnDBPath            string
	CVEPaths              []string
	VendorAliasesPath     string
	ProductAliasesPath    string
	ProductIgnoreListPath string
	MSRCDataPath          string
	//CiscoDataPath          string
	ProductPlatformMapping map[string][]string
}

// Validate returns true if the params `p` are set and valid.
func (p CreateDBParams) Validate() bool {
	if len(p.VulnDBPath) == 0 {
		return false
	}

	if len(p.CVEPaths) == 0 {
		return false
	}

	if len(p.VendorAliasesPath) == 0 {
		return false
	}

	if len(p.ProductAliasesPath) == 0 {
		return false
	}

	if len(p.ProductIgnoreListPath) == 0 {
		return false
	}

	return true
}

// CreateDB processes the NVD files and creates the Nanitor Vulnerability DB as an SQLite file db.
func CreateDB(params CreateDBParams) error {
	if params.Validate() == false {
		return errors.New("invalid params")
	}

	// Remove if exists.
	os.Remove(params.VulnDBPath)

	orm, err := xorm.NewEngine("sqlite3", params.VulnDBPath)
	if err != nil {
		return err
	}
	defer orm.Close()

	//For debugging:
	//orm.ShowSQL(true)

	sessionw := NewSessionWrapper(orm)
	defer sessionw.CommitAndClose()

	err = sessionw.Exec(createVulnDBSchema)
	if err != nil {
		return err
	}

	// Load NVD CVE data into vulndb.
	err = processNVDCVE(sessionw, params.CVEPaths)
	if err != nil {
		log.Debugf("ERROR: Problem processing NVDCVE: %v", err)
		return err
	}

	// Scrapes windows 10 versions.
	err = processWindowsVersions(sessionw)
	if err != nil {
		return err
	}

	// Process vendor aliases.
	err = processVendorAliases(sessionw, params.VendorAliasesPath)
	if err != nil {
		return err
	}

	// Process product aliases.
	err = processProductAliases(sessionw, params.ProductAliasesPath)
	if err != nil {
		return err
	}

	// Process ignore list.
	err = processProductIgnoreList(sessionw, params.ProductIgnoreListPath)
	if err != nil {
		return err
	}

	err = processMSRCData(sessionw, params.MSRCDataPath)
	if err != nil {
		return err
	}

	err = processRedhatOvalData(sessionw)
	if err != nil {
		return err
	}

	//err = processCiscoData(sessionw, params.CiscoDataPath, params.ProductPlatformMapping)
	//if err != nil {
	//	return err
	//}

	err = sessionw.CommitAndClose()
	if err != nil {
		return err
	}

	return nil
}

// processNVDCVE loads and processes NVD CVE advisories, outputting to the Nanitor vulndb.
// `cvePaths` specifies an input slice of NVD CVE files to be processed, e.g. 2002-2018.
func processNVDCVE(sessionw *VulnDBSession, cvePaths []string) error {
	var platforms []platforms
	if err := sessionw.curSession.Find(&platforms); err != nil {
		return err
	}
	platformMapping := make(map[int64][]*regexp.Regexp)
	for _, p := range platforms {
		for _, exp := range strings.Split(p.Rule, ",") {
			platformMapping[p.ID] = append(platformMapping[p.ID], regexp.MustCompile(exp))
		}
	}
	platformVulnExist := make(map[string]bool)
	for _, cvePath := range cvePaths {
		log.Debugf("Processing %s", cvePath)
		cveDir, err := loadNVDCVEJSON(cvePath, 4.0)
		if err != nil {
			return err
		}

		advisoryIDs := map[string]int64{}

		// Advisories
		for _, cve := range cveDir.Advisories {
			advisory := NVDCVEAdvisory{}
			advisory.CVEID = cve.CVEID
			advisory.Summary = cve.Summary
			advisory.PublishedAt = cve.PublishedAtInt
			advisory.LastModifiedAt = cve.LastModifiedAtInt

			if cve.CVSS2 != nil {
				score := cve.CVSS2.BaseScore
				advisory.CVSS2BaseScore = &score
				advisory.CVSS2AccessVector = cve.CVSS2.AccessVector
				advisory.CVSS2AccessComplexity = cve.CVSS2.AccessComplexity
				advisory.CVSS2Authentication = cve.CVSS2.Authentication
				advisory.CVSS2ConfidentialityImpact = cve.CVSS2.ConfidentialityImpact
			}
			if cve.CVSS3 != nil {
				advisory.CVSS3BaseScore = &cve.CVSS3.BaseScore
				advisory.CVSS3AttackComplexity = cve.CVSS3.AttackComplexity
				advisory.CVSS3AttackVector = cve.CVSS3.AttackVector
				advisory.CVSS3AvailabilityImpact = cve.CVSS3.AvailabilityImpact
				advisory.CVSS3ConfidentialityImpact = cve.CVSS3.ConfidentialityImpact
				advisory.CVSS3IntegrityImpact = cve.CVSS3.IntegrityImpact
				advisory.CVSS3PrivilegesRequired = cve.CVSS3.PrivilegesRequired
				advisory.CVSS3Scope = cve.CVSS3.Scope
				advisory.CVSS3UserInteraction = cve.CVSS3.UserInteraction
				advisory.CVSS3VectorString = &cve.CVSS3.VectorString
				advisory.CVSS3ExploitabilityScore = cve.CVSS3.ExploitabilityScore
			}

			if len(cve.VendorRefURL) > 0 {
				advisory.VendorRefUrl = &cve.VendorRefURL
			}
			// TODO: Clean up, kind of hacky.  Ideally would store as part of the cvss3 vector.
			//   (as part of temporal info).
			if cve.HasPatch != nil {
				val := 0
				if *cve.HasPatch {
					val = 1
				}
				advisory.HasPatch = &val
			}
			if cve.ReportConfirmed != nil {
				val := 0
				if *cve.ReportConfirmed {
					val = 1
				}
				advisory.ReportConfirmed = &val
			}

			err := sessionw.Insert(&advisory)
			if err != nil {
				return err
			}

			advisoryIDs[advisory.CVEID] = advisory.Id
		}

		// Vulnerabilities down to systype - vendor - product - version - patch/update.
		for systype, vendormap := range cveDir.Map {
			for vendorName, prodmap := range vendormap {
				var vendor VulndbVendor
				has, err := sessionw.Where("name = ?", vendorName).Get(&vendor)
				if err != nil {
					return err
				}
				if !has {
					vendor.Name = vendorName
					err := sessionw.Insert(&vendor)
					if err != nil {
						return err
					}
				}

				for prodName, entries := range prodmap {
					for _, entry := range entries {
						// Create entry for platform_vulnerabilities.
						if systype == "o" {
							// Insert platform_vulnerabilities.
							for platformID, rules := range platformMapping {
								for _, r := range rules {
									if r.MatchString(entry.RawCPE23) {
										var platformVuln platformVulnerabilities
										platformVuln.PlatformID = platformID
										platformVuln.VulnerabilityId = advisoryIDs[entry.CVEID]
										platformVuln.Source = SourceCPE
										key := fmt.Sprintf("%v:%v", platformVuln.PlatformID, platformVuln.VulnerabilityId)
										if _, has := platformVulnExist[key]; !has {
											err = sessionw.Insert(&platformVuln)
											if err != nil {
												return err
											}
											platformVulnExist[key] = true
										}
									}
								}
							}
						}
						// Get or create product.
						var prod vulndbProduct
						has, err := sessionw.Where("vendor_id = ? AND product_name = ?", vendor.ID, prodName).Get(&prod)
						if err != nil {
							return err
						}
						if !has {
							prod.VendorID = vendor.ID
							prod.ProductName = prodName
							err := sessionw.Insert(&prod)
							if err != nil {
								return err
							}
						}

						// Get or create product item.
						whereSQL := `product_id = ? AND systype = ?`
						params := []interface{}{prod.ID, systype}
						if entry.Version != nil && *entry.Version != "*" {
							whereSQL += ` AND version = ?`
							params = append(params, *entry.Version)
						}
						if entry.VersionStartExcluding != nil {
							whereSQL += ` AND version_start_excluding = ?`
							params = append(params, *entry.VersionStartExcluding)
						}
						if entry.VersionStartIncluding != nil {
							whereSQL += ` AND version_start_including = ?`
							params = append(params, *entry.VersionStartIncluding)
						}
						if entry.VersionEndExcluding != nil {
							whereSQL += ` AND version_end_excluding = ?`
							params = append(params, *entry.VersionEndExcluding)
						}
						if entry.VersionEndIncluding != nil {
							whereSQL += ` AND version_end_including = ?`
							params = append(params, *entry.VersionEndIncluding)
						}
						if len(entry.Update) > 0 && entry.Update != "*" {
							whereSQL += ` AND patch = ?`
							params = append(params, entry.Update)
						}
						var prodItem vulndbProductItem
						has, err = sessionw.Where(whereSQL, params...).Get(&prodItem)
						if err != nil {
							return err
						}
						if !has {
							prodItem.ProductID = prod.ID
							prodItem.Systype = systype
							if entry.Version != nil && *entry.Version != "*" {
								prodItem.Version = entry.Version
							}
							prodItem.VersionStartExcluding = entry.VersionStartExcluding
							prodItem.VersionStartIncluding = entry.VersionStartIncluding
							prodItem.VersionEndExcluding = entry.VersionEndExcluding
							prodItem.VersionEndIncluding = entry.VersionEndIncluding
							if len(entry.Update) > 0 && entry.Update != "*" {
								prodItem.Patch = entry.Update
							}
							if len(entry.SWTarget) > 0 && entry.SWTarget != "*" {
								swTarget := entry.SWTarget
								prodItem.SWTarget = &swTarget
							}
							err = sessionw.Insert(&prodItem)
							if err != nil {
								return err
							}
						}

						// Insert vuln.
						var vuln vulndbVulnerability
						vuln.ProductItemID = prodItem.ID
						vuln.AdvisoryID = advisoryIDs[entry.CVEID]
						err = sessionw.Insert(&vuln)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	return nil
}

// processVendorAliases loads vendor aliases for XML and puts into vulndb.
func processVendorAliases(sessionw *VulnDBSession, vendorAliasesPath string) error {
	valiases, err := loadVendorAliases(vendorAliasesPath)
	if err != nil {
		return err
	}

	for _, item := range valiases.Aliases {
		var vendor VulndbVendor
		has, err := sessionw.Where("name = ?", item.ForName).Get(&vendor)
		if err != nil {
			return err
		}
		if !has {
			log.Debugf("ERROR - Vendor '%s' not present", item.ForName)
			return errors.New("Vendor not present")
		}

		var valias VulndbVendorAlias
		valias.VendorID = vendor.ID
		valias.Alias = item.Alias
		err = sessionw.Insert(&valias)
		if err != nil {
			return err
		}
	}

	return nil
}

// processProductAliases loads product aliases for XML and puts into vulndb.
func processProductAliases(sessionw *VulnDBSession, productAliasesPath string) error {
	aliases, err := loadProductAliases(productAliasesPath)
	if err != nil {
		return err
	}

	for _, product := range aliases.Products {
		// Get vendor (original).
		var vendor VulndbVendor
		has, err := sessionw.Where("name = ?", product.Vendor).Get(&vendor)
		if err != nil {
			return err
		}
		if !has {
			log.Debugf("ERROR - Vendor '%s' not present", product.Vendor)
			return errors.New("Vendor not present")
		}

		// Get product (original).
		var vdbProduct vulndbProduct
		has, err = sessionw.Where(`vendor_id = ? AND product_name = ?`, vendor.ID, product.Product).Get(&vdbProduct)
		if err != nil {
			return err
		}
		if !has {
			log.Debugf("ERROR - Product '%s' not present", product.Product)
			return errors.New("Product not present")
		}

		for _, a := range product.Aliases {
			var palias vulndbProductAlias
			palias.ProductID = vdbProduct.ID
			palias.ProductAlias = a.Product
			palias.VendorAlias = a.Vendor

			err := sessionw.Insert(&palias)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// processProductIgnoreList processes vendor/product ignore list and inserts into VulnDB.
func processProductIgnoreList(sessionw *VulnDBSession, ignoreListPath string) error {
	ignoreList, err := loadProductIgnoreList(ignoreListPath)
	if err != nil {
		return err
	}

	for _, item := range ignoreList.Items {
		var ign vulndbIgnoreListItem
		ign.VendorName = item.VendorName
		ign.ProductNameGlob = item.ProductGlob
		err := sessionw.Insert(&ign)
		if err != nil {
			return err
		}
	}
	return nil
}

func processMSRCData(sessionw *VulnDBSession, msrcJSONPath string) error {
	content, err := ioutil.ReadFile(msrcJSONPath)
	if err != nil {
		return err
	}
	data := msrcapi.Result{}
	if err := json.Unmarshal(content, &data); err != nil {
		return err
	}
	var platforms []platforms
	if err := sessionw.curSession.Find(&platforms); err != nil {
		return err
	}
	platformMappingRules := make(map[int64][]*regexp.Regexp)
	for _, p := range platforms {
		for _, exp := range strings.Split(p.Rule, ",") {
			platformMappingRules[p.ID] = append(platformMappingRules[p.ID], regexp.MustCompile(exp))
		}
	}
	uniquePlatformVuln := make(map[string]bool)
	for cveID, patchInfo := range data.Vulnerabilities {
		var advisory NVDCVEAdvisory
		has, err := sessionw.Where("cve_id = ?", cveID).Get(&advisory)
		if err != nil {
			return err
		}
		if !has {
			fmt.Printf("CVE not found in NVD: %s - adding\n", cveID)
			advisory.CVEID = cveID
			if err = sessionw.Insert(&advisory); err != nil {
				return err
			}
		}
		for _, info := range patchInfo {
			for platformID, rules := range platformMappingRules {
				if isPlatformMatchRulePassed(rules, info.Product) {
					var platformVuln platformVulnerabilities
					platformVuln.PlatformID = platformID
					platformVuln.VulnerabilityId = advisory.Id
					platformVuln.Source = SourceMSRC
					key := fmt.Sprintf("%v:%v", platformVuln.PlatformID, platformVuln.VulnerabilityId)
					if _, ok := uniquePlatformVuln[key]; !ok {
						err = sessionw.Insert(&platformVuln)
						if err != nil {
							return err
						}
						uniquePlatformVuln[key] = true
					}
				}
			}
		}
	}
	return nil
}

func isPlatformMatchRulePassed(rules []*regexp.Regexp, value string) bool {
	for _, rule := range rules {
		if rule.MatchString(value) {
			return true
		}
	}
	return false
}

func processWindowsVersions(session *VulnDBSession) error {
	c := colly.NewCollector()
	uniqueVersion := make(map[string]bool)
	versions := []windows10_versions{}
	c.OnHTML("#winrelinfo_container", func(body *colly.HTMLElement) {
		body.ForEach("table", func(_ int, el *colly.HTMLElement) {
			el.ForEach("tbody tr", func(_ int, row *colly.HTMLElement) {
				channel := row.ChildText("td:nth-child(2)")
				if strings.HasPrefix(channel, "Semi-Annual Channel") ||
					strings.HasPrefix(channel, "Long-Term Servicing") {
					if _, ok := uniqueVersion[row.ChildText("td:nth-child(1)")]; !ok {
						versions = append(versions, windows10_versions{
							Version:          row.ChildText("td:nth-child(1)"),
							OsBuild:          row.ChildText("td:nth-child(4)"),
							AvailabilityDate: row.ChildText("td:nth-child(3)"),
						})
						uniqueVersion[row.ChildText("td:nth-child(1)")] = true
					}
				}
			})
		})
	})
	c.OnRequest(func(r *colly.Request) {})
	c.Visit("https://winreleaseinfoprod.blob.core.windows.net/winreleaseinfoprod/en-US.html")
	fmt.Printf("Adding %v windows10 versions\n", len(versions))
	for _, v := range versions {
		err := session.Insert(&v)
		if err != nil {
			return err
		}
	}
	return nil
}
