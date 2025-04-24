package ci

type TokenCheckResponse struct {
	Expired     bool `json:"expired"`
	Permissions []struct {
		Label       string   `json:"label"`
		Permissions []string `json:"permissions"`
	} `json:"permissions"`
	PersonalAccessTokenId string `json:"personalAccessTokenId"`
	// Code string `json:"code"`
}

type PluginRepo struct {
	PersonalAccessTokenID string                `gorm:"column:personal_access_token_id;" json:",omitempty"`
	RepoName              string                `gorm:"column:repo_name;" json:",omitempty"`
	PluginType            string                `gorm:"foreignkey:plugin_type" json:",omitempty"`
	VulnerabilityAnalysis VulnerabilityAnalysis `gorm:"foreignkey:vulnerability_analysis" json:",omitempty"`
}

type VulnerabilityAnalysis struct {
	RepositoryID   string `gorm:"references:id;foreignKey:repository_id" json:",omitempty"`
	ImageID        string `gorm:"column:image_id;" json:",omitempty"`
	ImportedRepoID string `gorm:"column:imported_repo_id" json:",omitempty"`
	PluginRepoID   string `gorm:"references:id;foreignKey:plugin_repo_id" json:",omitempty"`
	Status         string `gorm:"column:status;size:255" json:",omitempty"`
	Duration       string `gorm:"column:duration;size:255" json:",omitempty"`
	Critical       int64  `gorm:"column:critical;" json:",omitempty"`
	High           int64  `gorm:"column:high;" json:",omitempty"`
	Medium         int64  `gorm:"column:medium;" json:",omitempty"`
	Low            int64  `gorm:"column:low;" json:",omitempty"`
	Negligible     int64  `gorm:"column:negligible;" json:",omitempty"`
	Unknown        int64  `gorm:"column:unknown;" json:",omitempty"`
	Os             int32  `gorm:"column:os;" json:",omitempty"`
	App            int32  `gorm:"column:app;" json:",omitempty"`
	//relationships
	// Components []*Component `gorm:"references:id;foreignKey:vulnerability_analysis_id;" json:",omitempty"`
}

type Component struct {
	VulnerabilityAnalysisID *string `gorm:"column:vulnerability_analysis_id;" json:",omitempty"`
	BOMAnalysisID           *string `gorm:"column:bom_analysis_id;" json:",omitempty"`
	Name                    string  `gorm:"column:name;" json:",omitempty"`
	Type                    string  `gorm:"column:type;" json:",omitempty"`
	Version                 string  `gorm:"column:version;" json:",omitempty"`
	Path                    string  `gorm:"column:path;" json:",omitempty"`
	PURL                    string  `gorm:"column:purl;" json:",omitempty"`
	Description             string  `gorm:"column:description;" json:",omitempty"`
	Metadata                string  `gorm:"column:description;type:text;" json:",omitempty"`

	//relationships
	Vulnerabilities []*Vulnerability `gorm:"references:id;foreignKey:component_id" json:",omitempty"`
	CPEs            []*CPE           `gorm:"references:id;foreignKey:component_id" json:",omitempty"`
	Licenses        []*License       `gorm:"references:id;foreignKey:component_id" json:",omitempty"`
	Locations       []*Location      `gorm:"references:id;foreignKey:component_id" json:",omitempty"`
}

type Vulnerability struct {
	ComponentID    string `gorm:"column:component_id;" json:",omitempty"`
	CVE            string `gorm:"column:cve;size:255;" json:",omitempty"`
	Package        string `gorm:"column:package;size:255;" json:",omitempty"`
	CurrentVersion string `gorm:"column:current_version;size:255;" json:",omitempty"`
	VersionRange   string `gorm:"column:version_range;size:255;" json:",omitempty"`
	Description    string `gorm:"column:description;type:text;" json:",omitempty"`
	//Relationships
	CVSS CVSS `gorm:"references:id;foreignKey:vulnerability_id" json:",omitempty"`
}

type CVSS struct {
	VulnerabilityID string `gorm:"column:vulnerability_id;" json:",omitempty"`
	Version         string `gorm:"column:version;size:255;" json:",omitempty"`
	BaseScore       string `gorm:"column:base_score;size:255;" json:",omitempty"`
	Severity        string `gorm:"column:severity;size:255;" json:",omitempty"`
}

type CPE struct {
	ComponentID string `gorm:"column:component_id;size:255" json:",omitempty"`
	CPE         string `gorm:"column:cpe;size:255" json:",omitempty"`
}

type License struct {
	ComponentID   string `gorm:"column:component_id;size:255" json:",omitempty"`
	LicenseName   string `gorm:"column:license_name;size:255" json:",omitempty"`
	ComponentName string `gorm:"column:package_name;size:255" json:",omitempty"`
}

type Location struct {
	ComponentID string `gorm:"column:component_id;" json:",omitempty"`
	Path        string `gorm:"column:path;size:255;" json:",omitempty"`
	LayerHash   string `gorm:"column:layer_hash;size:255;" json:",omitempty"`
}
