package helper

import "strings"

func SplitConstraints(constraints string) []string {
	// Split the constraint string by commas, semicolons, or whitespace
	// and return a slice of individual constraints.
	// Split the constraints by comma
	constraintSlice := []string{constraints}
	if strings.Contains(constraints, " || ") {
		constraintSlice = strings.Split(constraints, " || ")
	}

	return constraintSlice
}

func SplitConstraintsByComma(constraints string) []string {
 // Split the constraint string by commas and return a slice of individual constraints.
 // This is useful for cases where constraints are separated by commas.
 return strings.Split(constraints, ", ")
}