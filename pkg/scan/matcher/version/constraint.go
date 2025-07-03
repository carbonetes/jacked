package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Constraint represents a version constraint for vulnerability matching
type Constraint struct {
	Operator string // e.g., ">=", "<=", "=", "!=", "~", "^"
	Version  string
}

// Parse parses version constraint strings into structured constraints
func Parse(constraintStr string) ([]Constraint, error) {
	if constraintStr == "" {
		return nil, nil
	}

	// Split by comma for multiple constraints
	parts := strings.Split(constraintStr, ",")
	var constraints []Constraint

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		constraint, err := parseConstraint(part)
		if err != nil {
			return nil, fmt.Errorf("failed to parse constraint '%s': %w", part, err)
		}

		constraints = append(constraints, constraint)
	}

	return constraints, nil
}

// parseConstraint parses a single constraint
func parseConstraint(s string) (Constraint, error) {
	s = strings.TrimSpace(s)

	// Check for operators
	operators := []string{">=", "<=", "!=", "=", "~", "^", ">", "<"}

	for _, op := range operators {
		if strings.HasPrefix(s, op) {
			version := strings.TrimSpace(s[len(op):])
			return Constraint{
				Operator: op,
				Version:  version,
			}, nil
		}
	}

	// If no operator, assume exact match
	return Constraint{
		Operator: "=",
		Version:  s,
	}, nil
}

// Check checks if a given version satisfies the constraints
func Check(version string, constraints []Constraint) bool {
	if len(constraints) == 0 {
		return true // No constraints means all versions match
	}

	for _, constraint := range constraints {
		if !checkConstraint(version, constraint) {
			return false
		}
	}

	return true
}

// checkConstraint checks if a version satisfies a single constraint
func checkConstraint(version string, constraint Constraint) bool {
	switch constraint.Operator {
	case "=", "==":
		return compareVersions(version, constraint.Version) == 0
	case "!=", "<>":
		return compareVersions(version, constraint.Version) != 0
	case ">":
		return compareVersions(version, constraint.Version) > 0
	case ">=":
		return compareVersions(version, constraint.Version) >= 0
	case "<":
		return compareVersions(version, constraint.Version) < 0
	case "<=":
		return compareVersions(version, constraint.Version) <= 0
	case "~":
		return checkTildeConstraint(version, constraint.Version)
	case "^":
		return checkCaretConstraint(version, constraint.Version)
	default:
		// Unknown operator, assume exact match
		return compareVersions(version, constraint.Version) == 0
	}
}

// compareVersions compares two version strings
// Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
func compareVersions(v1, v2 string) int {
	// Simple semantic version comparison
	parts1 := parseVersionParts(v1)
	parts2 := parseVersionParts(v2)

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		var p1, p2 int

		if i < len(parts1) {
			p1 = parts1[i]
		}
		if i < len(parts2) {
			p2 = parts2[i]
		}

		if p1 < p2 {
			return -1
		} else if p1 > p2 {
			return 1
		}
	}

	return 0
}

// parseVersionParts parses version string into numeric parts
func parseVersionParts(version string) []int {
	// Remove common prefixes
	version = strings.TrimPrefix(version, "v")
	version = strings.TrimPrefix(version, "V")

	// Split by dots and parse numbers
	parts := strings.Split(version, ".")
	var result []int

	for _, part := range parts {
		// Extract only the numeric part (ignore pre-release identifiers)
		numPart := strings.FieldsFunc(part, func(r rune) bool {
			return !(r >= '0' && r <= '9')
		})

		if len(numPart) > 0 {
			if num, err := strconv.Atoi(numPart[0]); err == nil {
				result = append(result, num)
			} else {
				result = append(result, 0)
			}
		} else {
			result = append(result, 0)
		}
	}

	return result
}

// checkTildeConstraint checks tilde (~) constraints (compatible version)
func checkTildeConstraint(version, constraint string) bool {
	// ~ allows patch-level changes if a minor version is specified
	// ~1.2.3 := >=1.2.3 <1.(2+1).0 := >=1.2.3 <1.3.0
	// ~1.2 := >=1.2.0 <1.(2+1).0 := >=1.2.0 <1.3.0
	// ~1 := >=1.0.0 <(1+1).0.0 := >=1.0.0 <2.0.0

	cParts := parseVersionParts(constraint)

	if len(cParts) == 0 {
		return true
	}

	// Must be >= constraint
	if compareVersions(version, constraint) < 0 {
		return false
	}

	// Check upper bound based on constraint precision
	if len(cParts) >= 2 {
		// Has minor version, increment minor
		upperBound := make([]int, len(cParts))
		copy(upperBound, cParts)
		upperBound[1]++ // Increment minor
		if len(upperBound) > 2 {
			upperBound[2] = 0 // Reset patch
		}

		upperVersion := formatVersion(upperBound)
		return compareVersions(version, upperVersion) < 0
	} else if len(cParts) == 1 {
		// Only major version, increment major
		upperBound := []int{cParts[0] + 1, 0, 0}
		upperVersion := formatVersion(upperBound)
		return compareVersions(version, upperVersion) < 0
	}

	return true
}

// checkCaretConstraint checks caret (^) constraints (compatible version)
func checkCaretConstraint(version, constraint string) bool {
	// ^ allows changes that do not modify the left-most non-zero digit
	// ^1.2.3 := >=1.2.3 <2.0.0
	// ^0.2.3 := >=0.2.3 <0.3.0
	// ^0.0.3 := >=0.0.3 <0.0.4

	cParts := parseVersionParts(constraint)

	if len(cParts) == 0 {
		return true
	}

	// Must be >= constraint
	if compareVersions(version, constraint) < 0 {
		return false
	}

	// Find the left-most non-zero digit
	for i, part := range cParts {
		if part > 0 {
			// Increment this digit for upper bound
			upperBound := make([]int, len(cParts))
			copy(upperBound, cParts)
			upperBound[i]++

			// Reset all digits to the right
			for j := i + 1; j < len(upperBound); j++ {
				upperBound[j] = 0
			}

			upperVersion := formatVersion(upperBound)
			return compareVersions(version, upperVersion) < 0
		}
	}

	return true
}

// formatVersion formats version parts back to string
func formatVersion(parts []int) string {
	var strs []string
	for _, part := range parts {
		strs = append(strs, strconv.Itoa(part))
	}
	return strings.Join(strs, ".")
}
