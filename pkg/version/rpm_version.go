package version

import (
	rpm "github.com/knqyf263/go-rpm-version"
)

type rpmVersion struct {
	raw    string
	rpmVer rpm.Version
}

func NewRPMVersion(version string) (*rpmVersion, error) {
	v := rpm.NewVersion(version)
	return &rpmVersion{
		raw:    version,
		rpmVer: v,
	}, nil
}
