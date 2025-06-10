package version

import (
	"fmt"
	"strings"
)

func (a *apkVersion) Check(constraints string) (bool, error) {
	if len(constraints) == 0 {
		return false, fmt.Errorf("constraints is empty")
	}

	// Split the constraints by comma
	constraintSlice := []string{constraints}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	}

	for _, constraint := range constraintSlice {
		// Create a new semantic constraint
		c, err := newSemanticConstraint(constraint)
		if c == nil || err != nil {
			// If the constraint is nil or an error occurred, skip this constraint
			return false, err
		}
		// Check if the constraint is valid
		if !c.isValid(constraint) {
			// If the constraint is not valid, skip this constraint
			return false, fmt.Errorf("invalid constraint: %s", constraint)
		}
		// Check if the apk version satisfies the constraint
		if satisfied, err := c.check(a.semanticVersion); err == nil && satisfied {
			// If the apk version satisfies the constraint, return true
			return true, nil
		}
	}

	return false, nil
}
