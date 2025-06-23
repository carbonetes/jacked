package version

import (
	"strings"

	pep440_version "github.com/aquasecurity/go-pep440-version"
)

func (v *PEP440Version) Check(constraints string) (bool, error) {
	if len(constraints) == 0 {
		return false, NoConstraintError
	}

	// Split the constraints by commas
	constraintSlice := []string{}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	} else {
		constraintSlice = append(constraintSlice, constraints)
	}

	for _, constraint := range constraintSlice {
		// Normalize the PEP 440 version constraint
		normalizedConstraint, err := normalizePEP440VersionConstraint(constraint)
		if err != nil {
			return false, err
		}

		// Check if the PEP 440 version satisfies the constraint
		satisfies, err := checkPEP440VersionConstraint(v.pep440Ver, normalizedConstraint)
		if err != nil {
			return false, err
		}

		if satisfies {
			// If any constraint is satisfied, return true
			return true, nil
		}
	}

	return false, nil
}

func normalizePEP440VersionConstraint(constraint string) (string, error) {
	if len(constraint) == 0 {
		return "", NoConstraintError
	}

	// Extract the version part from the constraint
	parts := strings.Split(constraint, " ")
	if len(parts) != 2 {
		return "", InvalidConstraintError
	}

	versionPart := parts[1]

	pep440Ver, err := NewPEP440Version(versionPart)
	if err != nil {
		return "", ErrInvalidConstraintFormat
	}

	// Normalize the version part by using its raw representation
	return strings.Join([]string{parts[0], pep440Ver.raw}, " "), nil
}

// checkPEP440VersionConstraint checks if the given PEP 440 version satisfies the specified constraint.
func checkPEP440VersionConstraint(pep440Ver *pep440_version.Version, constraint string) (bool, error) {
	if len(constraint) == 0 {
		return false, NoConstraintError
	}

	// Split the constraint into operator and version
	parts := strings.Split(constraint, " ")
	if len(parts) != 2 {
		return false, InvalidConstraintError
	}
	operator := parts[0]
	versionStr := parts[1]

	// Parse the version string
	constraintVer, err := pep440_version.Parse(versionStr)
	if err != nil {
		return false, ErrInvalidConstraintFormat
	}

	//  Check the operator against the PEP 440 version
	// Use the appropriate method based on the operator then return the result
	switch operator {
	case "==":
		return pep440Ver.Equal(constraintVer), nil
	case "<":
		return pep440Ver.LessThan(constraintVer), nil
	case "<=":
		return pep440Ver.LessThanOrEqual(constraintVer), nil
	case ">":
		return pep440Ver.GreaterThan(constraintVer), nil
	case ">=":
		return pep440Ver.GreaterThanOrEqual(constraintVer), nil
	default:
		return false, ErrInvalidConstraintOperator
	}
}
