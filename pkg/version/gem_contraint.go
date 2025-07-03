package version

import (
	"github.com/carbonetes/jacked/internal/helper"
	hashicorp "github.com/hashicorp/go-version"
)

func (gv *GemVersion) Check(constraintStr string) (bool, error) {
	if constraintStr == "" {
		return false, ErrNoConstraint
	}

	constraintSlice := helper.SplitConstraints(constraintStr)
	for _, constraint := range constraintSlice {
		cons, err := hashicorp.NewConstraint(constraint)
		if err != nil {
			return false, err
		}

		if cons.Check(gv.semanticVersion) {
			return true, nil
		}
	}

	return false, nil
}
