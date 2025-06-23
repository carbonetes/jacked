package version

import (
	"fmt"
	"strings"

	"github.com/carbonetes/jacked/internal/helper"
	rpm "github.com/knqyf263/go-rpm-version"
)

func (a *rpmVersion) Check(expression string) (bool, error) {
	if expression == "" {
		return false, fmt.Errorf("constraints is empty")
	}

	if strings.Contains(expression, " || ") { // Handle OR constraints
		return a.checkOrConstraints(expression)
	}
	return a.checkSingleConstraint(expression)
}

func (a *rpmVersion) checkOrConstraints(expression string) (bool, error) {
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
					return false, fmt.Errorf(errCheckFormat, a.raw, comparator, err)
				}
				return true, nil // If single constraint matches, return true
			}
		}
	}
	return false, nil // If no constraints match, return false
}

func (a *rpmVersion) checkAndConstraints(comparator string) (bool, error) {
	constraints := strings.Split(comparator, ", ")
	if len(constraints) != 2 {
		return false, fmt.Errorf("invalid constraint format: %s", comparator)
	}
	if satisfied, err := a.check(constraints[0]); satisfied || err != nil {
		if err != nil {
			return false, fmt.Errorf(errCheckFormat, a.raw, constraints[0], err)
		}
		if satisfied, err = a.check(constraints[1]); satisfied || err != nil {
			if err != nil {
				return false, fmt.Errorf(errCheckFormat, a.raw, constraints[1], err)
			}
			return true, nil // If second constraint matches, return true
		}
	}
	return false, nil
}

func (a *rpmVersion) checkSingleConstraint(expression string) (bool, error) {
	if satisfied, err := a.check(expression); satisfied || err != nil {
		if err != nil {
			return false, fmt.Errorf(errCheckFormat, a.raw, expression, err)
		}
		return true, nil // If single constraint matches, return true
	}
	return false, nil // If no constraints match, return false
}

func (a *rpmVersion) check(constraint string) (bool, error) {
	parts := strings.Split(constraint, " ")
	if len(parts) != 2 {
		return false, fmt.Errorf("invalid constraint format: %s", constraint)
	}
	operator := parts[0]
	versionStr := parts[1]
	v := rpm.NewVersion(versionStr)
	switch operator {
	case "<":
		return a.rpmVer.LessThan(v), nil
	case "<=":
		return a.rpmVer.LessThan(v) || a.rpmVer.Equal(v), nil
	case ">":
		return a.rpmVer.GreaterThan(v), nil
	case ">=":
		return a.rpmVer.GreaterThan(v) || a.rpmVer.Equal(v), nil
	case "==", "=":
		return a.rpmVer.Equal(v), nil
	}
	return false, fmt.Errorf("unknown operator: %s", operator)
}
