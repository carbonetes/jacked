package version

import (
	"fmt"
	"strings"

	"github.com/carbonetes/jacked/internal/helper"
	apk "github.com/knqyf263/go-apk-version"
)

const errCheckFormat = "error checking apk version %s against constraint %s: %w"

func (a *apkVersion) Check(expression string) (bool, error) {
	if expression == "" {
		return false, fmt.Errorf("constraints is empty")
	}

	if strings.Contains(expression, " || ") { // Handle OR constraints
		return a.checkOrConstraints(expression)
	}
	return a.checkSingleConstraint(expression)
}

func (a *apkVersion) checkOrConstraints(expression string) (bool, error) {
	comparators := helper.SplitConstraints(expression)
	for _, comparator := range comparators {
		if strings.Contains(comparator, ", ") {
			satisfied, err := a.checkAndConstraints(comparator)
			if satisfied || err != nil {
				return satisfied, err
			}
		} else {
			if satisfied, err := a.check(comparator); satisfied || err != nil {
				if err != nil {
					return false, fmt.Errorf(errCheckFormat, a.apkVer, comparator, err)
				}
				return true, nil // If single constraint matches, return true
			}
		}
	}
	return false, nil // If no constraints match, return false
}

func (a *apkVersion) checkAndConstraints(comparator string) (bool, error) {
	constraints := strings.Split(comparator, ", ")
	if len(constraints) != 2 {
		return false, fmt.Errorf("invalid constraint format: %s", comparator)
	}
	if satisfied, err := a.check(constraints[0]); satisfied || err != nil {
		if err != nil {
			return false, fmt.Errorf(errCheckFormat, a.apkVer, constraints[0], err)
		}
		if satisfied, err = a.check(constraints[1]); satisfied || err != nil {
			if err != nil {
				return false, fmt.Errorf(errCheckFormat, a.apkVer, constraints[1], err)
			}
			return true, nil // If second constraint matches, return true
		}
	}
	return false, nil
}

func (a *apkVersion) checkSingleConstraint(expression string) (bool, error) {
	if satisfied, err := a.check(expression); satisfied || err != nil {
		if err != nil {
			return false, fmt.Errorf(errCheckFormat, a.apkVer, expression, err)
		}
		return true, nil // If single constraint matches, return true
	}
	return false, nil // If no constraints match, return false
}

func (a *apkVersion) check(constraint string) (bool, error) {
	parts := strings.Split(constraint, " ")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid constraint format: %s", constraint)
	}
	operator := parts[0]
	versionStr := parts[1]
	v, err := apk.NewVersion(versionStr)
	if err != nil {
		return false, fmt.Errorf("failed to parse version: %s, error: %w", versionStr, err)
	}

	if a.apkVer == nil {
		return false, fmt.Errorf("apk version is not initialized")
	}

	switch operator {
	case "<":
		return a.apkVer.LessThan(v), nil
	case "<=":
		return a.apkVer.LessThan(v) || a.apkVer.Equal(v), nil
	case ">":
		return a.apkVer.GreaterThan(v), nil
	case ">=":
		return a.apkVer.GreaterThan(v) || a.apkVer.Equal(v), nil
	case "==":
		return a.apkVer.Equal(v), nil
	}
	return false, fmt.Errorf("unknown operator: %s", operator)
}
