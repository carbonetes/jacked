package ci

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/carbonetes/jacked/internal/log"
	"golang.org/x/exp/slices"
)

type Assessment struct {
	Tally        Tally
	FailCriteria string
	Matches      []Match
	Passed       bool
}

type Match struct {
	Component     *cyclonedx.Component
	Vulnerability *cyclonedx.Vulnerability
}

type Tally struct {
	Unknown    int
	Negligible int
	Low        int
	Medium     int
	High       int
	Critical   int
}

func Evaluate(criteria string, cdx *cyclonedx.BOM) Assessment {
	assessment := Assessment{}
	var index int
	criteria = strings.ToUpper(criteria)
	for i, severity := range Severities {
		if strings.EqualFold(severity, criteria) {
			index = i
		}
	}

	severities := Severities[index:]
	log.Printf("Evaluating vulnerabilities with criteria: %v", severities)
	var tally Tally
	for index, v := range *cdx.Vulnerabilities {
		if v.Ratings == nil {
			tally.Unknown++
			continue
		}
		if len(*v.Ratings) == 0 {
			tally.Unknown++
			continue
		}
		for _, r := range *v.Ratings {
			if slices.Contains(severities, strings.ToLower(string(r.Severity))) {
				match := newMatch(&(*cdx.Vulnerabilities)[index], cdx.Components)
				assessment.Matches = append(assessment.Matches, match)

			}

			switch strings.ToLower(string(r.Severity)) {
			case "negligible":
				tally.Negligible++
			case "low":
				tally.Low++
			case "medium":
				tally.Medium++
			case "high":
				tally.High++
			case "critical":
				tally.Critical++
			default:
				tally.Unknown++
			}
		}
	}
	assessment.Tally = tally
	if len(assessment.Matches) == 0 {
		assessment.Passed = true
	}

	return assessment
}

func newMatch(v *cyclonedx.Vulnerability, comps *[]cyclonedx.Component) Match {
	match := Match{}
	for index, c := range *comps {
		if v.BOMRef == c.BOMRef {
			match.Component = &(*comps)[index]
			match.Vulnerability = v
		}
	}
	return match
}
