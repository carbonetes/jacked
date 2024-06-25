package debian

import (
	"errors"
	"regexp"
)

type Constraint struct {
	Operator string
	Version  Version
}

func (c *Constraint) Check(v Version) bool {
	compResult := v.Compare(&c.Version)
	switch c.Operator {
	case "==":
		return compResult == debianVersionEqual
	case ">":
		return compResult == debianVersionGreater
	case "<":
		return compResult == debianVersionLess
	case ">=":
		return compResult == debianVersionGreater || compResult == debianVersionEqual
	case "<=":
		return compResult == debianVersionLess || compResult == debianVersionEqual
	default:
		return false
	}
}

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
		Version:  *version,
	}, nil
}
