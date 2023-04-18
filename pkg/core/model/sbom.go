package model

import "encoding/json"

type SBOM struct {
	Packages json.RawMessage `json:"packages"`
	Secrets json.RawMessage `json:"secrets"`
	ImageInfo json.RawMessage `json:"imageInfo"`
	Distro json.RawMessage `json:"distro"`
}
