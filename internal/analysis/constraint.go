package analysis

import (
	"github.com/carbonetes/jacked/internal/model"
	"github.com/hashicorp/go-version"
)

func MatchConstraint(packageVersion string, criteria model.Criteria) (bool, string) {
	v, err := version.NewVersion(packageVersion)
	if err!= nil {
        return false, ""
    }

	for _, constraint := range criteria.Constraints {
		c, err := version. NewConstraint(constraint)
		if err != nil {
			continue
		}

		if c.Check(v) {
            return true, constraint
        }
	}

	return false, ""
}