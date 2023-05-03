package assessment

import (
	"strings"

	"github.com/CycloneDX/cyclonedx-go"
	"golang.org/x/exp/slices"
)

type Assessment struct {
	Tally        *Tally
	FailCriteria string
	Matches      *[]Match
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

var Severities = []string{
	"UNKNOWN",
	"NEGLIGIBLE",
	"LOW",
	"MEDIUM",
	"HIGH",
	"CRITICAL",
}

func Evaluate(criteria *string, cdx *cyclonedx.BOM) *Assessment {
	assessment := new(Assessment)
	if criteria == nil || len(*criteria) == 0 {
		return nil
	}

	if !slices.Contains(Severities, strings.ToUpper(*criteria)) {
		return nil
	}

	var index int
	for i, severity := range Severities {
		if severity == strings.ToUpper(*criteria) {
			index = i
		}
	}

	severities := Severities[index:]
	var tally Tally
	assessment.Matches = new([]Match)
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
			if slices.Contains(severities, strings.ToUpper(string(r.Severity))) {
				match := newMatch(&(*cdx.Vulnerabilities)[index], cdx.Components)
				*assessment.Matches = append(*assessment.Matches, *match)

			}

			switch r.Severity {
			case "NEGLIGIBLE":
				tally.Negligible++
			case "LOW":
				tally.Low++
			case "MEDIUM":
				tally.Medium++
			case "HIGH":
				tally.High++
			case "CRITICAL":
				tally.Critical++
			default:
				tally.Unknown++
			}
		}
	}
	assessment.Tally = &tally
	if len(*assessment.Matches) == 0 {
		assessment.Passed = true
	}

	return assessment
}

func newMatch(v *cyclonedx.Vulnerability, comps *[]cyclonedx.Component) *Match {
	match := new(Match)
	for index, c := range *comps {
		if v.BOMRef == c.BOMRef {
			match.Component = &(*comps)[index]
			match.Vulnerability = v
		}
	}
	return match
}
