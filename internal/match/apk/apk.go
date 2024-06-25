package apk

import (
	"strings"
)

func CheckConstraint(constraints []string, packageVersion string) (string, bool) {
	if len(constraints) == 0 {
		return "", false
	}

	for _, constraint := range constraints {
		if strings.Contains(constraint, ", ") {
			parts := strings.Split(constraint, ", ")
			if len(parts) > 1 {
				constraint1, err := NewConstraint(parts[0])
				if err != nil {
					return "", false
				}

				constraint2, err := NewConstraint(parts[1])
				if err != nil {
					return "", false
				}

				if constraint1.Check(Version(packageVersion)) && constraint2.Check(Version(packageVersion)) {
					return constraint, true
				}

			}
		} else {
			c, err := NewConstraint(constraint)
			if err != nil {
				return "", false
			}

			if c.Check(Version(packageVersion)) {
				return constraint, true
			}
		}
	}

	return "", false
}
