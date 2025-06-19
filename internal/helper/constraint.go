package helper

import (
	"regexp"
	"strings"
)

// Split the constraint string by commas, semicolons, or whitespace
// and return a slice of individual constraints.
// Split the constraints by comma
func SplitConstraints(constraints string) []string {

	constraintSlice := []string{constraints}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	}

	return constraintSlice
}

// Split the constraint string by commas and return a slice of individual constraints.
// This is useful for cases where constraints are separated by commas.
func SplitConstraintsByComma(constraints string) []string {
	return strings.Split(constraints, ", ")
}

// NormalizeVersion ensures the version has major, minor, and patch numbers.
// Example: "1" -> "1.0.0", "1.2" -> "1.2.0", "1.2.3" -> "1.2.3"
// Handles suffixes like "-r5", "_git20230717-r5", and "_preN-rN"
func NormalizeVersion(version string) string {
	// Remove known suffixes like _gitYYYYMMDD-rN, _preN-rN, or -rN
	reSuffix := regexp.MustCompile(`(_git[0-9]+)?(_pre[0-9]+)?-r[0-9]+$`)
	version = reSuffix.ReplaceAllString(version, "")

	// Now normalize the version numbers
	regex := regexp.MustCompile(`^([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?$`)
	matches := regex.FindStringSubmatch(version)
	if matches == nil {
		return version // return as-is if it doesn't match
	}
	parts := []string{matches[1]}
	if matches[2] != "" {
		parts = append(parts, matches[2])
	} else {
		parts = append(parts, "0")
	}
	if matches[3] != "" {
		parts = append(parts, matches[3])
	} else {
		parts = append(parts, "0")
	}
	return strings.Join(parts, ".")
}
