package model

type ScanResult struct {
	Package         Package  `json:"package"`
	Vulnerabilities []Result `json:"vulnerabilities"`
}
type Result struct {
	CVE            string `json:"cve"`
	Package        string `json:"package"`
	CurrentVersion string `json:"current_version"`
	VersionRange   string `json:"version_range"`
	Description    string `json:"description"`
	CVSS           CVSS   `json:"cvss"`
}

type CVSS struct {
	Version   string  `json:"version"`
	BaseScore float64 `json:"base_score"`
	Severity  string  `json:"severity"`
}
