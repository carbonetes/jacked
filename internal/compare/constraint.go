package compare

import (
	"errors"
	"regexp"
	"strings"

	"github.com/hashicorp/go-version"
)

const (
	VersionEqual   = 0
	VersionLess    = -1
	VersionGreater = 1
)

var constraintRegex = regexp.MustCompile(`(>=|<=|>|<|=)\s*(.+)`)

func parseSingleConstraint(singleRawConstraint string) ([]string, error) {
	matches := constraintRegex.FindStringSubmatch(singleRawConstraint)
	if matches == nil {
		return nil, errors.New("invalid constraint format")
	}

	if len(matches) != 3 {
		return nil, errors.New("invalid constraint format")
	}

	return matches, nil
}

func parseMultiConstraint(multiRawConstraint string) ([][]string, error) {
	constraints := strings.Split(multiRawConstraint, ", ")
	if len(constraints) == 0 {
		return nil, errors.New("invalid constraint format")
	}

	res := make([][]string, len(constraints))
	for i, constraint := range constraints {
		parts, err := parseSingleConstraint(constraint)
		if err != nil {
			return nil, err
		}
		res[i] = parts
	}

	return res, nil
}

// Using semver to compare versions and constraints, this function will return true if the package version satisfies the constraint.
func MatchGenericConstraint(packageVersion *string, constraints string) (bool, string) {
	if len(constraints) == 0 {
		return false, ""
	}

	if strings.Contains(constraints, " || ") {
		constraintSlice := strings.Split(constraints, " || ")
		for _, constraint := range constraintSlice {
			v, err := version.NewVersion(normalizeVersion(*packageVersion))
			if err != nil {
				return false, ""
			}

			c, err := version.NewConstraint(normalizeConstraint(constraint))
			if err != nil {
				return false, ""
			}

			if c.Check(v) {
				return true, constraint
			}
		}
	}

	return false, ""
}

// try to normalize the version string to a valid semver string
func normalizeConstraint(constraint string) string {
	if strings.Contains(constraint, ", ") {
		constraints := strings.Split(constraint, ", ")
		for i, c := range constraints {
			parts := strings.Split(c, " ")
			if len(parts) > 1 {
				parts[1] = normalizeVersion(parts[1])
				c = strings.Join(parts, " ")
				constraints[i] = c
			}

		}
		constraint = strings.Join(constraints, ", ")
	} else {
		parts := strings.Split(constraint, " ")
		if len(parts) > 1 {
			parts[1] = normalizeVersion(parts[1])
		}
		constraint = strings.Join(parts, " ")
	}
	return constraint
}

// remove any non-numeric characters from the version string and try to normalize it to a valid semver string
func normalizeVersion(version string) string {

	parts := strings.Split(version, ".")
	if len(parts) >= 3 {
		var v []string
		regex := regexp.MustCompile("[0-9]+")
		major := regex.FindString(parts[0])
		minor := regex.FindString(parts[1])
		patch := regex.FindString(parts[2])
		v = append(v, major)
		v = append(v, minor)
		v = append(v, patch)
		version = strings.Join(v, ".")
	} else if len(parts) == 2 {
		var v []string
		regex := regexp.MustCompile("[0-9]+")
		major := regex.FindString(parts[0])
		minor := regex.FindString(parts[1])
		v = append(v, major)
		v = append(v, minor)
		version = strings.Join(v, ".")
	}

	if strings.Contains(version, ":") {
		parts := strings.Split(version, ":")
		if len(parts) > 1 {
			version = parts[1]
		}
	}

	// Replace any occurrences of "_final" or "-final" with an empty string.
	version = strings.Replace(version, "_final", "", -1)
	version = strings.Replace(version, "v", "", -1)
	version = strings.Replace(version, "-final", "", -1)

	// Replace any occurrences of "-rc" or "-b" with an empty string, followed by a dot.
	version = strings.Replace(version, "-rc", ".", -1)
	version = strings.Replace(version, ".r", ".", -1)
	version = strings.Replace(version, "-b", ".", -1)

	// Replace any occurrences of "-" with a dot.
	version = strings.Replace(version, "-", ".", -1)

	return version
}
