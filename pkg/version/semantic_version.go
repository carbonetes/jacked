package version

import (
	"errors"
	"regexp"
	"strconv"

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

func compareSemver(v1, v2 string) int {
	// Split the version strings into their components
	re := regexp.MustCompile(`(\d+)`)
	v1Parts := re.FindAllString(v1, -1)
	v2Parts := re.FindAllString(v2, -1)

	// Compare each part of the version
	for i := 0; i < len(v1Parts) && i < len(v2Parts); i++ {
		v1Part, _ := strconv.Atoi(v1Parts[i])
		v2Part, _ := strconv.Atoi(v2Parts[i])

		if v1Part < v2Part {
			return -1
		} else if v1Part > v2Part {
			return 1
		}
	}

	// If all parts are equal, compare the lengths of the version strings
	if len(v1Parts) < len(v2Parts) {
		return -1
	} else if len(v1Parts) > len(v2Parts) {
		return 1
	}

	return 0
}
