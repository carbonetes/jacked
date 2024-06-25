package match

import "github.com/carbonetes/jacked/internal/match/debian"

func matchDebian(m Matcher) {
	if m.Matches == nil || len(m.Matches) == 0 {
		return
	}

	found := []*Found{}
	for _, match := range m.Matches {
		constraint, result := debian.CheckConstraint(match.Constraints, m.Component.Version)
		if result {
			found = append(found, &Found{
				Match:      match,
				Constraint: constraint,
			})
		}
	}
}
