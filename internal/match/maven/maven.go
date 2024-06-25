package maven

import (
	"strings"

	version "github.com/masahiro331/go-mvn-version"
)

func CheckConstraint(constraints []string, packageVersion string) (string, bool) {
	if len(constraints) == 0 {
		return "", false
	}

	pv, err := version.NewVersion(packageVersion)
	if err != nil {
		return "", false
	}

	for _, constraint := range constraints {
		if strings.Contains(constraint, ", ") {
			parts := strings.Split(constraint, ", ")
			if len(parts) > 1 {
				constraint1, err := version.NewConstraints(parts[0])
				if err != nil {
					return "", false
				}

				constraint2, err := version.NewConstraints(parts[1])
				if err != nil {
					return "", false
				}

				if constraint1.Check(pv) && constraint2.Check(pv) {
					return constraint, true
				}

			}
		} else {
			c, err := version.NewConstraints(constraint)
			if err != nil {
				return "", false
			}

			if c.Check(pv) {
				return constraint, true
			}
		}
	}
	return "", false
}
