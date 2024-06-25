package constraint

import (
	"regexp"
	"strings"

	"github.com/hashicorp/go-version"
)

func Check(constraints []string, packageVersion string) (string, bool) {
	if len(constraints) == 0 {
		return "", false
	}

	packageVersion = normalizeVersion(packageVersion)

	for _, constraint := range constraints {
		if strings.Contains(constraint, ", ") {
			parts := strings.Split(constraint, ", ")
			if len(parts) > 1 {
				constraint1, err := version.NewConstraint(normalizeConstraint(parts[0]))
				if err != nil {
					return "", false
				}

				constraint2, err := version.NewConstraint(normalizeConstraint(parts[1]))
				if err != nil {
					return "", false
				}

				if constraint1.Check(version.Must(version.NewVersion(packageVersion))) && constraint2.Check(version.Must(version.NewVersion(packageVersion))) {
					return constraint, true
				}

			}
		} else {
			constraint, err := version.NewConstraint(normalizeConstraint(constraint))
			if err != nil {
				return "", false
			}

			if constraint.Check(version.Must(version.NewVersion(packageVersion))) {
				return constraint.String(), true
			}
		}
	}

	return "", false
}

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
