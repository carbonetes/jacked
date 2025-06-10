package version

import (
	"fmt"
	"strings"
)

// normalizeDpkgVersion normalizes a dpkg version string
// by removing the epoch and replacing the version separator
// with a hyphen. It also handles the case where the
// version string contains a tilde (~) character.
func normalizeDpkgVersionContraint(constraint *string) {
	if constraint == nil || len(*constraint) == 0 {
		return
	}

	constraintSlice := strings.Split(*constraint, " ")
	if len(constraintSlice) == 0 || len(constraintSlice) != 2 {
		return
	}

	// Normalize the version part of the constraint
	dpkgVersion, err := NewDpkgVersion(constraintSlice[1])
	if err != nil {
		return
	}

	// Normalize the upstream version
	upstreamVersion := normalizeUpstreamVersion(dpkgVersion.raw.upstream)
	// Replace the version part of the constraint with the normalized version
	*constraint = strings.Replace(*constraint, constraintSlice[1], upstreamVersion, 1)
}

func (d *dpkgVersion) Check(constraints string) (bool, error) {
	if len(constraints) == 0 {
		return false, fmt.Errorf("constraints is empty")
	}

	// Split the constraints by comma
	constraintSlice := []string{constraints}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	}

	for _, constraint := range constraintSlice {
		// Normalize the dpkg version constraint
		normalizeDpkgVersionContraint(&constraint)
		// Create a new semantic constraint
		c, err := newSemanticConstraint(constraint)
		if c == nil || err != nil {
			// If the constraint is nil or an error occurred, return false and the error
			return false, err
		}

		// Check if the constraint is valid
		if !c.isValid(constraint) {
			// If the constraint is not valid, return false and the error
			return false, err
		}

		// Check if the dpkg version satisfies the constraint
		if satisfied, err := c.check(d.semanticVersion); err == nil && satisfied {
			// If the dpkg version satisfies the constraint, return true
			return true, nil
		}

	}

	return false, nil
}
