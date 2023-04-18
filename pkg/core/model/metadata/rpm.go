package model

type RpmMetadata struct {
	Architecture    string `json:"architecture"`
	DigestAlgorithm string `json:"digestAlgorithm"`
	License         string `json:"license"`
	Name            string `json:"name"`
	PGP             string `json:"pgp"`
	Release         string `json:"release"`
	Size            int64  `json:"size"`
	SourceRpm       string `json:"sourceRpm"`
	Summary         string `json:"summary"`
	Vendor          string `json:"vendor"`
	Version         string `json:"version"`
}
