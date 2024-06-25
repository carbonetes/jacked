package debian

import "strings"

func CheckConstraint(constraints []string, packageVersion string) (string, bool) {
	if len(constraints) == 0 {
		return "", false
	}
	pv, err := NewVersion(packageVersion)
	if err != nil {
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

				if constraint1.Check(*pv) && constraint2.Check(*pv) {
					return "", false
				}

			}
		} else {
			constraint, err := NewConstraint(constraint)
			if err != nil {
				return "", false
			}

			if constraint.Check(*pv) {
				return "", false
			}
		}
	}

	return "", false
}
