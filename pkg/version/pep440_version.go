package version

import pep440_version "github.com/aquasecurity/go-pep440-version"

type PEP440Version struct {
	raw       string
	pep440Ver *pep440_version.Version
}

func NewPEP440Version(version string) (*PEP440Version, error) {
	if len(version) == 0 {
		return nil, ErrNoVersion
	}

	pep440Ver, err := pep440_version.Parse(version)
	if err != nil {
		return nil, err
	}

	return &PEP440Version{
		raw:       version,
		pep440Ver: &pep440Ver,
	}, nil
}
