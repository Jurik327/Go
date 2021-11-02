package vulndb

// CVEDirectory represents NVD CVE entries from an NVD CVE xml file.
type CVEDirectory struct {
	// Map is a mapping of
	// systype -> vendor -> product -> []cveDirEntries {specific product items)
	Map map[string]map[string]map[string][]cveDirEntry
	// List of loaded CVE advisories.
	Advisories []CVEAdvisory
}

// CVEAdvisory represents an CVE item from the NVD CVE feed.
type CVEAdvisory struct {
	CVEID             string
	Summary           string
	PublishedAtInt    int64
	LastModifiedAtInt int64
	CVSS2             *CVECVSS2
	CVSS3             *CVECVSS3
	VendorRefURL      string
	HasPatch          *bool
	ReportConfirmed   *bool
}

// CVECVSS2 represents common CVSS2 impact scores for CVE advisories.
type CVECVSS2 struct {
	BaseScore             float64
	AccessVector          *int
	AccessComplexity      *int
	Authentication        *int
	ConfidentialityImpact *int
}

// CVECVSS3 represents common CVSS3 impact scores for CVE advisories.
type CVECVSS3 struct {
	AttackComplexity      *int
	AttackVector          *int
	AvailabilityImpact    *int
	BaseScore             float64
	BaseSeverity          int
	ConfidentialityImpact *int
	IntegrityImpact       *int
	PrivilegesRequired    *int
	Scope                 *int
	UserInteraction       *int
	VectorString          string
	ExploitabilityScore   *int
}

type cveDirEntry struct {
	CVEID                 string
	Version               *string
	VersionStartExcluding *string
	VersionStartIncluding *string
	VersionEndExcluding   *string
	VersionEndIncluding   *string
	Update                string
	Arch                  string
	SWTarget              string
	RawCPE23              string
}
