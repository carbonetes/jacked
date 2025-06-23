package version

import (
	"errors"
	"regexp"

	hashicorp "github.com/hashicorp/go-version"
)

func NewSemanticVersion(version string) (*hashicorp.Version, error) {
	if len(version) == 0 {
		return nil, NoVersionError
	}
	if !isValidSemver(version) {
		return nil, errors.New("invalid semantic version format")
	}

	semVer, err := hashicorp.NewVersion(version)
	if err != nil {
		return nil, err
	}

	return semVer, nil
}

func isValidSemver(v string) bool {
	// Check if the version string matches the semantic version format
	re := regexp.MustCompile(`^(\d+)\.(\d+)\.(\d+)$`)
	return re.MatchString(v)
}
