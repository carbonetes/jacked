package version

import "strings"

func normalizeMavenVersionConstraint(constraint string) string {
	if len(constraint) == 0 {
		return ""
	}

	// Extract the version part from the constraint
	parts := strings.Split(constraint, " ")
	if len(parts) != 2 {
		return ""
	}

	versionPart := parts[1]

	mavenVersion, err := NewMavenVersion(versionPart)
	if err != nil {
		return ""
	}

	// Normalize the version part by removing any qualifiers or timestamps
	versionPart = normalizeMavenVersion(mavenVersion.raw)

	return strings.Join([]string{parts[0], versionPart}, " ")
}

func (m *mavenVersion) Check(constraints string) (bool, error) {
	if len(constraints) == 0 {
		return false, nil
	}

	// Split the constraints by comma
	constraintSlice := []string{}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	} else {
		constraintSlice = append(constraintSlice, constraints)
	}

	for _, constraint := range constraintSlice {
		// Normalize the maven version constraint
		normalizedConstraint := normalizeMavenVersionConstraint(constraint)
		if normalizedConstraint == "" {
			return false, nil
		}

		c, err := NewSemanticConstraint(normalizedConstraint)
		if c == nil || err != nil {
			return false, err
		}

		valid, err := c.check(m.semanticVersion)
		if err != nil || !valid {
			return false, err
		}
	}

	return true, nil
}
