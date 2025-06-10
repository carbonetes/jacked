package version

import "strings"

func normalizeGoVersionConstraint(constraint string) string {
	if len(constraint) == 0 {
		return ""
	}

	// Extract the version part from the constraint
	parts := strings.Split(constraint, " ")
	if len(parts) != 2 {
		return ""
	}

	versionPart := parts[1]

	// Normalize the version part by removing any qualifiers or timestamps
	versionPart = normalizeGoVersion(versionPart)

	return strings.Join([]string{parts[0], versionPart}, " ")
}

func (g *GoVersion) Check(constraints string) (bool, error) {
	if len(constraints) == 0 {
		return false, nil
	}

	// Split the constraints by comma
	constraintSlice := []string{constraints}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	}

	for _, constraint := range constraintSlice {
		// Normalize the Go version constraint
		normalizedConstraint := normalizeGoVersionConstraint(constraint)
		if normalizedConstraint == "" {
			return false, nil
		}

		c, err := newSemanticConstraint(normalizedConstraint)
		if c == nil || err != nil {
			return false, err
		}

		valid, err := c.check(g.raw)
		if err != nil || !valid {
			return false, err
		}
	}

	return true, nil
}