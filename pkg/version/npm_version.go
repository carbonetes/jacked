package version

import npm "github.com/aquasecurity/go-npm-version/pkg"

type NpmVersion struct {
	raw string
	npmVer npm.Version
}

func NewNpmVersion(raw string) (*NpmVersion, error) {
	npmVer, err := npm.NewVersion(raw)
	if err != nil {
		return nil, err
	}
	return &NpmVersion{
		raw:   raw,
		npmVer: npmVer,
	}, nil
}