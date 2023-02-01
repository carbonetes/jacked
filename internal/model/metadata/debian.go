package model

// DebianMetadata debian metadata
type DebianMetadataParser map[string]interface{}

type DebianMetadata struct {
	Architecture  string      `json:"Architecture"`
	Depends       string      `json:"Depends"`
	Breaks        string      `json:"Breaks"`
	Conffiles     []Conffiles `json:"Conffiles"`
	Description   string      `json:"Description"`
	Essential     string      `json:"Essential"`
	Homepage      string      `json:"Homepage"`
	InstalledSize string      `json:"Installed-Size"`
	Maintainer    string      `json:"Maintainer"`
	MultiArch     string      `json:"Multi-Arch"`
	Package       string      `json:"Package"`
	PreDepends    string      `json:"Pre-Depends"`
	Priority      string      `json:"Priority"`
	Section       string      `json:"Section"`
	Source        string      `json:"Source"`
	Status        string      `json:"Status"`
	Suggests      string      `json:"Suggests"`
	Version       string      `json:"Version"`
}

type Conffiles struct {
	Digest Digest `json:"digest"`
	Path   string `json:"path"`
}

type Digest struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}
