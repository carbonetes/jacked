package apk

import (
	"errors"
	"regexp"
)

// Constraint represents a version constraint.
type Constraint struct {
	Operator string
	Version  Version
}

// Check checks if the version satisfies the constraint.
func (c *Constraint) Check(v Version) bool {
    compResult := v.Compare(c.Version)
    switch c.Operator {
    case "==":
        return compResult == apkVersionEqual
    case ">":
        return compResult == apkVersionGreater
    case "<":
        return compResult == apkVersionLess
    case ">=":
        return compResult == apkVersionGreater || compResult == apkVersionEqual
    case "<=":
        return compResult == apkVersionLess || compResult == apkVersionEqual
    default:
        return false
    }
}

// NewConstraint parses a constraint string and returns a Constraint instance.
func NewConstraint(constraintStr string) (*Constraint, error) {
	re := regexp.MustCompile(`(>=|<=|>|<|==)\s*(.+)`)
	matches := re.FindStringSubmatch(constraintStr)
	if matches == nil {
		return nil, errors.New("invalid constraint format")
	}

	version, err := NewVersion(matches[2])
	if err != nil {
		return nil, err
	}

	return &Constraint{
		Operator: matches[1],
		Version:  version,
	}, nil
}
