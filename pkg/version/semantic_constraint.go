package version

import (
	"fmt"
	"log"
	"slices"
	"strings"

	hashicorp "github.com/hashicorp/go-version"
)

type semanticConstraint struct {
	raw        string
	constraint hashicorp.Constraints
	versionRaw string
	operator   string
}

func NewSemanticConstraint(constraintRaw string) (*semanticConstraint, error) {
	if len(constraintRaw) == 0 {
		return nil, fmt.Errorf("constraint is empty")
	}

	c, err := hashicorp.NewConstraint(constraintRaw)
	if err != nil {
		return nil, err
	}

	constraintSlice := strings.Split(constraintRaw, " ")
	if len(constraintSlice) == 0 || len(constraintSlice) != 2 {
		return nil, fmt.Errorf("invalid constraint format")
	}

	return &semanticConstraint{
		raw:        constraintRaw,
		constraint: c,
		versionRaw: constraintSlice[1],
		operator:   constraintSlice[0],
	}, nil
}

func (s *semanticConstraint) check(version string) (bool, error) {
	v, err := hashicorp.NewVersion(version)
	if err != nil {
		return false, err
	}

	return s.constraint.Check(v), nil
}

func (s *semanticConstraint) isValid(constraint string) bool {
	if len(constraint) == 0 {
		log.Printf("constraint is empty")
		return false
	}

	// Check if the constraint has a valid semantic version
	_, err := hashicorp.NewVersion(s.versionRaw)
	if err != nil {
		log.Printf("invalid semantic version: %s", s.versionRaw)
		return false
	}

	// Check if the operator is valid
	validOperators := []string{"<", "<=", ">", ">=", "==", "~=", "!="}
	return slices.Contains(validOperators, s.operator)
}