package model

type Output struct {
	Results  []ScanResult   `json:"results"`
	Licenses []License      `json:"licenses,omitempty"`
	Secrets  *SecretResults `json:"secrets,omitempty"`
}
