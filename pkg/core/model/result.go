package model

type ScanResult struct {
	Package         Package         `json:"package"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}
