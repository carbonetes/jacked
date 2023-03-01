package model

type Package struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Vendor      string      `json:"-"`
	Type        string      `json:"type"`
	Version     string      `json:"version"`
	Path        string      `json:"path"`
	Locations   []Location  `json:"locations"`
	Description string      `json:"description"`
	Licenses    []string    `json:"licenses"`
	CPEs        []string    `json:"cpes"`
	PURL        PURL        `json:"purl"`
	Metadata    interface{} `json:"metadata"`
	Keywords    []string    `json:"-"`
}

type PURL string

type Location struct {
	Path      string `json:"path"`
	LayerHash string `json:"layerHash"`
}
