// Package nvdjson decodes NVD JSON data feed.
package nvdjson

// NVD represents the National Vulnerability Database.
type NVD struct {
	CVEItems []CVEItem `json:"CVE_Items"`
}

// CVEItem represents a CVE including impact and vulnerable configurations.
type CVEItem struct {
	CVE            CVE `json:"cve"`
	Configurations struct {
		CVEDataVersion string              `json:"CVE_data_version"`
		Nodes          []ConfigurationNode `json:"nodes"`
	} `json:"configurations"`
	Impact struct {
		BaseMetricV3 *struct {
			CVSSV3              CVSSV3  `json:"cvssV3"`
			ExploitabilityScore float64 `json:"exploitabilityScore"`
			ImpactScore         float64 `json:"impactScore"`
		} `json:"baseMetricV3"`
		BaseMetricV2 *struct {
			CVSSV2                  CVSSV2  `json:"cvssV2"`
			Severity                string  `json:"severity"`
			ExploitabilityScore     float64 `json:"exploitabilityScore"`
			ImpactScore             float64 `json:"impactScore"`
			ObtainAllPrivilege      bool    `json:"obtainAllPrivilege"`
			ObtainUserPrivilege     bool    `json:"obtainUserPrivilege"`
			ObtainOtherPrivilege    bool    `json:"obtainOtherPrivilege"`
			UserInteractionRequired bool    `json:"userInteractionRequired"`
		} `json:"baseMetricV2"`
	} `json:"impact"`
	PublishedDate    string `json:"publishedDate"`
	LastModifiedDate string `json:"lastModifiedDate"`
}

type VulnerableItem struct {
	CPE23                 string
	VersionStartIncluding *string
	VersionStartExcluding *string
	VersionEndIncluding   *string
	VersionEndExcluding   *string
}

// VulnerableCPEs returns a list of vulnerable CPEs for CVE item `i`.
func (i CVEItem) VulnerableCPEs() ([]VulnerableItem, error) {
	var items []VulnerableItem

	for _, node := range i.Configurations.Nodes {
		nodeItems, err := node.VulnerableCPEs()
		if err != nil {
			return nil, err
		}
		items = append(items, nodeItems...)
	}

	return items, nil
}

type ReferenceItem struct {
	Name      string   `json:"name"`
	URL       string   `json:"url"`
	RefSource string   `json:"ref_source"`
	Tags      []string `json:"tags"`
}

func (r ReferenceItem) HasTag(tag string) bool {
	for _, t := range r.Tags {
		if t == tag {
			return true
		}
	}
	return false
}

func (r ReferenceItem) IsVendor() bool {
	return r.HasTag(ReferenceTagVendor)
}

func (i CVEItem) References() []ReferenceItem {
	var items []ReferenceItem

	for _, data := range i.CVE.References.Data {
		item := ReferenceItem{
			Name:      data.Name,
			URL:       data.Url,
			RefSource: data.RefSource,
			Tags:      data.Tags,
		}
		items = append(items, item)
	}

	return items
}

type ConfigurationNode struct {
	Operator   string              `json:"operator"`
	Children   []ConfigurationNode `json:"children,omitempty"`
	CPEMatches []CPEMatch          `json:"cpe_match,omitempty"`
}

// VulnerableCPEs returns a list of vulnerable CPEs for node `n`.
func (n ConfigurationNode) VulnerableCPEs() ([]VulnerableItem, error) {
	var items []VulnerableItem

	for _, childnode := range n.Children {
		childItems, err := childnode.VulnerableCPEs()
		if err != nil {
			return nil, err
		}
		items = append(items, childItems...)
	}

	for _, cpematch := range n.CPEMatches {
		if cpematch.Vulnerable {
			vitem := VulnerableItem{
				CPE23:                 cpematch.CPE23,
				VersionStartIncluding: cpematch.VersionStartIncluding,
				VersionStartExcluding: cpematch.VersionStartExcluding,
				VersionEndIncluding:   cpematch.VersionEndIncluding,
				VersionEndExcluding:   cpematch.VersionEndExcluding,
			}
			items = append(items, vitem)
		}
	}

	return items, nil
}

const (
	ReferenceTagVendor     = "Vendor Advisory"
	ReferenceTagThirdParty = "Third Party Advisory"
	ReferenceTagVDB        = "VDB Entry"
)

// CVE represents a single advisory from the NVD feed.
type CVE struct {
	DataType    string `json:"data_type"`
	DataFormat  string `json:"data_format"`
	DataVersion string `json:"data_version"`

	Meta struct {
		ID       string `json:"ID"`
		Assigner string `json:"ASSIGNER"`
	} `json:"CVE_data_meta"`

	ProblemType struct {
		Data []struct {
			Description []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"description"`
		} `json:"problemtype_data"`
	} `json:"problemtype"`

	References struct {
		Data []struct {
			Url       string   `json:"url"`
			Name      string   `json:"name"`
			RefSource string   `json:"refsource"`
			Tags      []string `json:"tags"`
		} `json:"reference_data"`
	} `json:"references"`

	Description struct {
		Data []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description_data"`
	} `json:"description"`
}

// GetDescription returns the English description of CVE.
func (c CVE) GetDescription() string {
	for _, data := range c.Description.Data {
		if data.Lang == "en" {
			return data.Value
		}
	}
	return ""
}

// CVSSV2 represents CVSSV2 scores for a given advisory.
type CVSSV2 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AccessVector          string  `json:"accessVector"`
	AccessComplexity      string  `json:"accessComplexity"`
	Authentication        string  `json:"authentication"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
}

// CVSSV3 represents CVSSV3 scores for a given advisory.
type CVSSV3 struct {
	Version               string  `json:"version"`
	VectorString          string  `json:"vectorString"`
	AttackVector          string  `json:"attackVector"`
	AttackComplexity      string  `json:"attackComplexity"`
	PrivilegesRequired    string  `json:"privilegesRequired"`
	UserInteraction       string  `json:"userInteraction"`
	Scope                 string  `json:"scope"`
	ConfidentialityImpact string  `json:"confidentialityImpact"`
	IntegrityImpact       string  `json:"integrityImpact"`
	AvailabilityImpact    string  `json:"availabilityImpact"`
	BaseScore             float64 `json:"baseScore"`
	BaseSeverity          string  `json:"baseSeverity"`
}

// CPEMatch represents a CPE match for a given advisory.
type CPEMatch struct {
	Vulnerable            bool    `json:"vulnerable"`
	CPE23                 string  `json:"cpe23Uri"`
	VersionStartIncluding *string `json:"versionStartIncluding,omitempty"`
	VersionStartExcluding *string `json:"versionStartExcluding,omitempty"`
	VersionEndIncluding   *string `json:"versionEndIncluding,omitempty"`
	VersionEndExcluding   *string `json:"versionEndExcluding,omitempty"`
}
