package match

import (
	"github.com/carbonetes/jacked/internal/match/apk"
)

func matchApk(m Matcher) []Found {
	if m.Matches == nil || len(m.Matches) == 0 {
		return nil
	}

	found := []Found{}
	for _, match := range m.Matches {
		constraint, result := apk.CheckConstraint(match.Constraints, m.Component.Version)
		if result {
			found = append(found, Found{
				Match:      match,
				Constraint: constraint,
			})
		}
	}
	return found
}
