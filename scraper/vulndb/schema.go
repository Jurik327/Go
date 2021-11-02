package vulndb

// createVulnDBSchema defines the schema for the vulndb (sqlite).
const createVulnDBSchema = `
CREATE TABLE vulndb_vendors(
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL
);
CREATE INDEX vulndb_vendors_name_idx ON vulndb_vendors(name);

CREATE TABLE vulndb_vendor_aliases(
  vendor_id INTEGER NOT NULL,
  alias TEXT NOT NULL
);
CREATE INDEX vulndb_vendor_aliases_alias_idx ON vulndb_vendor_aliases(alias);

CREATE TABLE vulndb_products(
  id INTEGER PRIMARY KEY,
  vendor_id INTEGER NOT NULL,
  product_name TEXT NOT NULL
);
CREATE INDEX vulndb_products_vendor_id_product_name_idx ON vulndb_products(vendor_id, product_name);
CREATE INDEX vulndb_products_vendor_id_idx ON vulndb_products(product_name);

CREATE TABLE vulndb_product_aliases(
  product_id INTEGER NOT NULL,
  vendor_alias TEXT NOT NULL,
  product_alias TEXT NOT NULL
);
CREATE INDEX vulndb_product_aliases_alias_idx ON vulndb_product_aliases(vendor_alias, product_alias);

CREATE TABLE vulndb_ignore_list(
	vendor_name TEXT NOT NULL,
	product_name_glob TEXT NOT NULL
);
CREATE INDEX vulndb_ignore_list_vendor_product_idx ON vulndb_ignore_list(vendor_name);

CREATE TABLE vulndb_product_items(
  id INTEGER PRIMARY KEY,
  product_id INTEGER NOT NULL,
  systype TEXT NOT NULL,
  version TEXT,
  version_start_excluding TEXT,
  version_start_including TEXT,
  version_end_excluding TEXT,
  version_end_including TEXT,
  sw_target TEXT,
  patch TEXT NOT NULL
);
CREATE INDEX vulndb_product_items_product_id_systype_version ON vulndb_product_items(product_id,systype,version);
CREATE INDEX vulndb_product_items_product_id_systype_version_patch_idx ON vulndb_product_items(product_id,systype,version,patch);

CREATE TABLE vulndb_vulnerabilities(
  product_item_id INTEGER NOT NULL,
  advisory_id INTEGER NOT NULL
);
CREATE INDEX vulndb_vulnerabilities_product_id_idx ON vulndb_vulnerabilities(product_item_id);

CREATE TABLE nvd_cve_advisories(
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  summary TEXT NOT NULL,
  published_at INTEGER NOT NULL,
  last_modified_at INTEGER NOT NULL,
  cvss2_base_score DOUBLE,
  cvss2_access_vector INTEGER,
  cvss2_access_complexity INTEGER,
  cvss2_authentication INTEGER,
  cvss2_confidentiality_impact INTEGER,
  cvss3_base_score DOUBLE,
  cvss3_attack_complexity INTEGER,
  cvss3_attack_vector INTEGER,
  cvss3_availability_impact INTEGER,
  cvss3_confidentiality_impact INTEGER,
  cvss3_integrity_impact INTEGER,
  cvss3_privileges_required INTEGER,
  cvss3_scope INTEGER,
  cvss3_user_interaction INTEGER,
  cvss3_vector_string TEXT,
  cvss3_exploitability_score INTEGER,
  vendor_ref_url TEXT,
  has_patch INTEGER,
  report_confirmed INTEGER
);

CREATE INDEX nvd_cve_advisories_cve_id_idx ON nvd_cve_advisories(cve_id);
CREATE INDEX nvd_cve_advisories_cvss2_base_score_idx ON nvd_cve_advisories(cvss2_base_score);
CREATE INDEX nvd_cve_advisories_cvss3_base_score_idx ON nvd_cve_advisories(cvss3_base_score);

CREATE TABLE vendor_cvss_entries(
  id INTEGER PRIMARY KEY,
  cve_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  last_crawled_at INTEGER NOT NULL,
  last_modified_at INTEGER NOT NULL,
  cvss3_vector_string TEXT NOT NULL,
  source TEXT NOT NULL
);
CREATE INDEX vendor_cvss_entries_cve_id_idx ON vendor_cvss_entries(cve_id);

CREATE TABLE platforms(
  id INTEGER PRIMARY KEY,
  rule TEXT NOT NULL,
  display_name TEXT NOT NULL
);
INSERT INTO platforms VALUES (1, ':o:centos:centos:6.0:', 'CentOS Linux 6');
INSERT INTO platforms VALUES (2, ':o:centos:centos:6.0:', 'CentOS Linux 7');
INSERT INTO platforms VALUES (3, ':o:centos:centos:6.0:', 'CentOS Linux 8');
INSERT INTO platforms VALUES (4, ':o:cisco:ios:', 'Cisco IOS');
INSERT INTO platforms VALUES (5, ':o:debian:debian_linux:10.0:', 'Debian Linux Buster 10');
INSERT INTO platforms VALUES (6, ':o:debian:debian_linux:9.0:', 'Debian Linux Stretch 9');
INSERT INTO platforms VALUES (7, ':o:microsoft:windows_10:,Microsoft Windows 10', 'Microsoft Windows 10');
INSERT INTO platforms VALUES (8, ':o:microsoft:windows_server_2008:r2,Windows Server 2008 R2', 'Microsoft Windows Server 2008 R2');
INSERT INTO platforms VALUES (9, ':o:microsoft:windows_server_2012:-:,Windows Server 2012', 'Microsoft Windows Server 2012');
INSERT INTO platforms VALUES (10, ':o:microsoft:windows_server_2012:r2:,Windows Server 2012 R2', 'Microsoft Windows Server 2012 R2');
INSERT INTO platforms VALUES (11, ':o:microsoft:windows_server_2016:,Windows Server 2016',  'Microsoft Windows Server 2016');
INSERT INTO platforms VALUES (12, ':o:microsoft:windows_server_2019:,Windows Server 2019', 'Microsoft Windows Server 2019');
INSERT INTO platforms VALUES (13, ':o:redhat:enterprise_linux:4.0:', 'Redhat Linux 4');
INSERT INTO platforms VALUES (14, ':o:redhat:enterprise_linux:5.0:', 'Redhat Linux 5');
INSERT INTO platforms VALUES (15, ':o:redhat:enterprise_linux:6.0:', 'Redhat Linux 6');
INSERT INTO platforms VALUES (16, ':o:redhat:enterprise_linux:7.0:', 'Redhat Linux 7');
INSERT INTO platforms VALUES (17, ':o:redhat:enterprise_linux:8.0:', 'Redhat Linux 8');
INSERT INTO platforms VALUES (18, ':o:oracle:solaris:', 'Solaris');
INSERT INTO platforms VALUES (19, ':o:canonical:ubuntu_linux:18.04:', 'Ubuntu Linux Bionic 1804');
INSERT INTO platforms VALUES (20, ':o:canonical:ubuntu_linux:16.04:', 'Ubuntu Linux Xenial 1604');
INSERT INTO platforms VALUES (21, ':o:canonical:ubuntu_linux:20.04:', 'Ubuntu Linux Focal 2004');

CREATE TABLE platform_vulnerabilities(
  platform_id INTEGER NOT NULL,
  vulnerability_id INTEGER NOT NULL,
  source TEXT
);
CREATE INDEX platform_vulnerabilities_vulnerability_id_idx ON platform_vulnerabilities(vulnerability_id);

CREATE TABLE windows10_versions(
   version TEXT PRIMARY KEY,
   os_build TEXT,
   availability_date TEXT
);
`

// VulndbVendor represents a vendor.
type VulndbVendor struct {
	ID   int64  `xorm:"pk autoincr 'id'"`
	Name string `xorm:"name"`
}

func (vendor VulndbVendor) TableName() string {
	return "vulndb_vendors"
}

// VulndbVendorAlias represents vendor aliases, e.g. "Microsoft Incorporated" -> "microsoft".
type VulndbVendorAlias struct {
	VendorID int64  `xorm:"vendor_id"`
	Alias    string `xorm:"alias"`
}

func (valias VulndbVendorAlias) TableName() string {
	return "vulndb_vendor_aliases"
}

// vulndbProduct represents a product identified by vendor, product name and other attributes.
type vulndbProduct struct {
	ID          int64  `xorm:"pk autoincr 'id'"`
	ProductName string `xorm:"product_name"`
	VendorID    int64  `xorm:"vendor_id"`
}

func (prod vulndbProduct) TableName() string {
	return "vulndb_products"
}

// vulndbProductItem represents a specific version/update of a product.
type vulndbProductItem struct {
	ID                    int64   `xorm:"pk autoincr 'id'"`
	ProductID             int64   `xorm:"product_id"`
	Systype               string  `xorm:"systype"`
	Version               *string `xorm:"'version'"`
	VersionStartExcluding *string `xorm:"version_start_excluding"`
	VersionStartIncluding *string `xorm:"version_start_including"`
	VersionEndExcluding   *string `xorm:"version_end_excluding"`
	VersionEndIncluding   *string `xorm:"version_end_including"`
	Patch                 string  `xorm:"patch"`
	SWTarget              *string `xorm:"sw_target"`
}

func (item vulndbProductItem) TableName() string {
	return "vulndb_product_items"
}

// vulndbProductAlias represents alias of product names, e.g. "Google Chrome" -> "chrome".
type vulndbProductAlias struct {
	ProductID    int64  `xorm:"product_id"`
	VendorAlias  string `xorm:"vendor_alias"`
	ProductAlias string `xorm:"product_alias"`
}

func (alias vulndbProductAlias) TableName() string {
	return "vulndb_product_aliases"
}

// vulndbIgnoreItem represents an item in the ignorelist.
type vulndbIgnoreListItem struct {
	VendorName      string `xorm:"vendor_name"`
	ProductNameGlob string `xorm:"product_name_glob"`
}

func (ign vulndbIgnoreListItem) TableName() string {
	return "vulndb_ignore_list"
}

// platforms represents the supported platforms.
type platforms struct {
	ID          int64  `xorm:"pk autoincr 'id'"`
	Rule        string `xorm:"rule"`
	DisplayName string `xorm:"display_name"`
}

func (p platforms) TableName() string {
	return "platforms"
}

// Constants for use in sqlite vulndb.
const (
	SourceCPE        = "cpe"         // CPE source used to get mapping of platform and vulnerability
	SourceMSRC       = "msrcAPI"     // MSRC API source used to get mapping of platform and vulnerability
	SourceRedhatOVAL = "redhat_oval" // redhat_oval source used to get mapping of platform and vulnerability
	SourceCisco      = "cisco"       // cisco source used to get mapping of platform and vulnerability
)

type platformVulnerabilities struct {
	PlatformID      int64  `xorm:"platform_id"`
	VulnerabilityId int64  `xorm:"vulnerability_id"`
	Source          string `xorm:"source"`
}

func (pv platformVulnerabilities) TableName() string {
	return "platform_vulnerabilities"
}

type windows10_versions struct {
	Version          string `xorm:"pk 'version'"`
	OsBuild          string `xorm:"os_build"`
	AvailabilityDate string `xorm:"availability_date"`
}

func (wv windows10_versions) TableName() string {
	return "windows10_versions"
}

// Constants for use in sqlite vulndb.
const (
	CVSSAccessVectorLocal           int = 100 // LOCAL
	CVSSAccessVectorNetwork         int = 200 // NETWORK
	CVSSAccessVectorAdjacentNetwork int = 300 // ADJACENT_NETWORK
)

const (
	CVSSAccessComplexityLow    int = 100 // LOW
	CVSSAccessComplexityMedium int = 200 // MEDIUM
	CVSSAccessComplexityHigh   int = 300 // HIGH
)

const (
	CVSSAuthenticationNone              int = 100 // NONE
	CVSSAuthenticationSingleInstance    int = 200 // SINGLE_INSTANCE
	CVSSAuthenticationMultipleInstances int = 300 // MULTIPLE_INSTANCES
)

const (
	CVSSConfidentialityImpactNone     int = 100 // NONE
	CVSSConfidentialityImpactPartial  int = 200 // PARTIAL
	CVSSConfidentialityImpactComplete int = 300 // COMPLETE
)

/// CVSS3.
const (
	AttackVectorTypeNetwork         int = 100 // "NETWORK"
	AttackVectorTypeAdjacentNetwork int = 200 // "ADJACENT_NETWORK"
	AttackVectorTypeLocal           int = 300 // "LOCAL"
	AttackVectorTypePhysical        int = 400 // "PHYSICAL"
)

const (
	ModifiedAttackVectorTypeNetwork         int = 100 // "NETWORK"
	ModifiedAttackVectorTypeAdjacentNetwork int = 200 // "ADJACENT_NETWORK"
	ModifiedAttackVectorTypeLocal           int = 200 // "LOCAL"
	ModifiedAttackVectorTypePhysical        int = 300 // "PHYSICAL"
	ModifiedAttackVectorTypeNotDefined      int = 400 // "NOT_DEFINED"
)

const (
	AttackComplexityTypeHigh int = 100 // "HIGH",
	AttackComplexityTypeLow  int = 200 // "LOW"
)

const (
	ModifiedAttackComplexityTypeHigh       int = 100 // "HIGH"
	ModifiedAttackComplexityTypeLow        int = 200 // "LOW"
	ModifiedAttackComplexityTypeNotDefined int = 300 // "NOT_DEFINED"
)

const (
	PrivilegesRequiredTypeHigh int = 100 // "HIGH"
	PrivilegesRequiredTypeLow  int = 200 // "LOW"
	PrivilegesRequiredTypeNone int = 300 // "NONE"
)

const (
	ModifiedPrivilegesRequiredTypeHigh       int = 100 // "HIGH"
	ModifiedPrivilegesRequiredTypeLow        int = 200 // "LOW"
	ModifiedPrivilegesRequiredTypeNone       int = 300 // "NONE"
	ModifiedPrivilegesRequiredTypeNotDefined int = 400 // "NOT_DEFINED"
)

const (
	UserInteractionTypeNone     int = 100 // "NONE"
	UserInteractionTypeRequired int = 200 // "REQUIRED"

)

const (
	ModifiedUserInteractionTypeNone       int = 100 // "NONE"
	ModifiedUserInteractionTypeRequired   int = 200 // "REQUIRED"
	ModifiedUserInteractionTypeNotDefined int = 300 // "NOT_DEFINED"
)

const (
	ScopeTypeUnchanged int = 100 // "UNCHANGED"
	ScopeTypeChanged   int = 200 // "CHANGED"
)

const (
	ModifiedScopeTypeUnchanged  int = 100 // "UNCHANGED"
	ModifiedScopeTypeChanged    int = 200 // "CHANGED"
	ModifiedScopeTypeNotDefined int = 300 // "NOT_DEFINED"
)

const (
	CiaTypeNone int = 100 // "NONE"
	CiaTypeLow  int = 200 // "LOW"
	CiaTypeHigh int = 300 // "HIGH"
)

const (
	ModifiedCiaTypeNone       int = 100 // "NONE"
	ModifiedCiaTypeLow        int = 200 // "LOW"
	ModifiedCiaTypeHigh       int = 300 // "HIGH"
	ModifiedCiaTypeNotDefined int = 400 // "NOT_DEFINED"
)

const (
	ExploitCodeMaturityTypeUnproven       int = 100 // "UNPROVEN"
	ExploitCodeMaturityTypeProofOfConcept int = 200 // "PROOF_OF_CONCEPT"
	ExploitCodeMaturityTypeFunctional     int = 300 // "FUNCTIONAL"
	ExploitCodeMaturityTypeHigh           int = 400 // "HIGH"
	ExploitCodeMaturityTypeNotDefined     int = 500 // "NOT_DEFINED"
)

const (
	RemediationLevelTypeOfficialFix  int = 100 // "OFFICIAL_FIX"
	RemediationLevelTypeTemporaryFix int = 200 // "TEMPORARY_FIX"
	RemediationLevelTypeWorkaround   int = 300 // "WORKAROUND"
	RemediationLevelTypeUnavailable  int = 400 // "UNAVAILABLE"
	RemediationLevelTypeNotDefined   int = 500 // "NOT_DEFINED"
)

const (
	ConfidenceTypeUnknown    int = 100 // "UNKNOWN"
	ConfidenceTypeReasonable int = 200 // "REASONABLE"
	ConfidenceTypeConfirmed  int = 300 // "CONFIRMED"
	ConfidenceTypeNotDefined int = 400 // "NOT_DEFINED"
)

const (
	CiaRequirementTypeLow        int = 100 // "LOW"
	CiaRequirementTypeMedium     int = 200 // "MEDIUM"
	CiaRequirementTypeHigh       int = 300 // "HIGH"
	CiaRequirementTypeNotDefined int = 400 // "NOT_DEFINED"
)

const (
	SeverityTypeNone     int = 100 // "NONE"
	SeverityTypeLow      int = 200 // "LOW"
	SeverityTypeMedium   int = 300 // "MEDIUM"
	SeverityTypeHigh     int = 400 // "HIGH"
	SeverityTypeCritical int = 500 // "CRITICAL"
)

// NVDCVEAdvisory represents NVD CVE advisories.
type NVDCVEAdvisory struct {
	Id             int64  `xorm:"pk autoincr 'id'"`
	CVEID          string `xorm:"cve_id"`
	Summary        string `xorm:"summary"`
	PublishedAt    int64  `xorm:"published_at"`
	LastModifiedAt int64  `xorm:"last_modified_at"`
	// CVSS2.
	CVSS2BaseScore             *float64 `xorm:"cvss2_base_score"`
	CVSS2AccessVector          *int     `xorm:"cvss2_access_vector"`
	CVSS2AccessComplexity      *int     `xorm:"cvss2_access_complexity"`
	CVSS2Authentication        *int     `xorm:"cvss2_authentication"`
	CVSS2ConfidentialityImpact *int     `xorm:"cvss2_confidentiality_impact"`
	// CVSS3.
	CVSS3BaseScore             *float64 `xorm:"cvss3_base_score"`
	CVSS3AttackComplexity      *int     `xorm:"cvss3_attack_complexity"`
	CVSS3AttackVector          *int     `xorm:"cvss3_attack_vector"`
	CVSS3AvailabilityImpact    *int     `xorm:"cvss3_availability_impact"`
	CVSS3ConfidentialityImpact *int     `xorm:"cvss3_confidentiality_impact"`
	CVSS3IntegrityImpact       *int     `xorm:"cvss3_integrity_impact"`
	CVSS3PrivilegesRequired    *int     `xorm:"cvss3_privileges_required"`
	CVSS3Scope                 *int     `xorm:"cvss3_scope"`
	CVSS3UserInteraction       *int     `xorm:"cvss3_user_interaction"`
	CVSS3VectorString          *string  `xorm:"cvss3_vector_string"`
	CVSS3ExploitabilityScore   *int     `xorm:"cvss3_exploitability_score"`

	VendorRefUrl    *string `json:"vendor_ref_url"`
	HasPatch        *int    `json:"has_patch"`
	ReportConfirmed *int    `json:"report_confirmed"`
}

func (cve NVDCVEAdvisory) TableName() string {
	return "nvd_cve_advisories"
}

// vulndbVulnerability connects vulnerable products with known CVEs.
type vulndbVulnerability struct {
	AdvisoryID    int64 `xorm:"advisory_id"`
	ProductItemID int64 `xorm:"product_item_id"`
}

func (vuln vulndbVulnerability) TableName() string {
	return "vulndb_vulnerabilities"
}

type VendorCVSSEntry struct {
	Id                int64  `xorm:"pk autoincr 'id'"`
	CVEID             string `xorm:"cve_id"`
	CreatedAt         int64  `xorm:"created_at"`
	LastModifiedAt    int64  `xorm:"last_modified_at"`
	LastCrawleddAt    int64  `xorm:"last_crawled_at"`
	CVSS3VectorString string `xorm:"cvss3_vector_string"`
	Source            string `xorm:"source"`
}

func (VendorCVSSEntry) TableName() string {
	return "vendor_cvss_entries"
}
