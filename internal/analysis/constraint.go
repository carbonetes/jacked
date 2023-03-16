package analysis

import "github.com/hashicorp/go-version"

func MatchConstraint(packageVersion string, constraints []string) (bool, string) {
	v, err := version.NewVersion(packageVersion)
	if err!= nil {
        return false, ""
    }

	for _, constraint := range constraints {
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