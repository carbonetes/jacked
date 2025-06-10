package version

import (
	hVersion "github.com/hashicorp/go-version"
	"strings"
)

type GoVersion struct {
	raw             string
	symanticVersion hVersion.Version
}

func NewGoVersion(version string) (*GoVersion, error) {
	if len(version) == 0 || version == "(devel)" {
		return nil, ErrInvalidVersionFormat
	}

	// Normalize the version string by removing any leading "v" or "go" prefix
	version = normalizeGoVersion(version)
	if len(version) == 0 {
		return nil, ErrInvalidVersionFormat
	}

	v, err := hVersion.NewVersion(version)
	if err != nil {
		return nil, err
	}

	return &GoVersion{
		raw:             version,
		symanticVersion: *v,
	}, nil
}

func normalizeGoVersion(version string) string {
	// Remove leading "v" or "go" prefix
	if len(version) > 0 && (version[0] == 'v' || version[0] == 'g') {
		version = version[1:]
	}
	// Remove any suffixes like "+incompatible"
	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}
	// Remove any suffixes like "-beta", "-rc", etc.
	if idx := strings.Index(version, "-"); idx != -1 {
		version = version[:idx]
	}
	// Remove any suffixes like "-devel"
	if idx := strings.Index(version, "(devel)"); idx != -1 {
		version = version[:idx]
	}

	return version
}
