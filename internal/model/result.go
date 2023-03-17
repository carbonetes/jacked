package model

type ScanResult struct {
	Package         Package  `json:"package"`
	Vulnerabilities []Result `json:"vulnerabilities"`
}
type Result struct {
	CVE            string       `json:"cve"`
	Package        string       `json:"package"`
	CurrentVersion string       `json:"current_version"`
	VersionRange   string       `json:"version_range"`
	Description    *Description `json:"description,omitempty"`
	CVSS           Cvss         `json:"cvss"`
	Remediation    Remediation  `json:"remediation"`
	Reference      Reference    `json:"reference"`
}
