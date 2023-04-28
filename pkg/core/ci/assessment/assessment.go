package assessment

import (
	"sync"

	"github.com/CycloneDX/cyclonedx-go"
)

type Assessment struct {
	Tally        *Tally
	FailCriteria *string
	Matches      *[]Match
	Passed       *bool
}

type Match struct {
	Component       *cyclonedx.Component
	Vulnerabilities []*cyclonedx.Vulnerability
}

type Tally struct {
	Unknown    int
	Negligible int
	Low        int
	Medium     int
	High       int
	Critical   int
}

func NewAssessment(t *Tally, criteria *string) *Assessment {
	return &Assessment{
		Tally:        t,
		FailCriteria: criteria,
		Matches:      new([]Match),
		Passed:       new(bool),
	}
}

func (a *Assessment) Check(cdx *cyclonedx.BOM) {
	var wg sync.WaitGroup

	wg.Add(len(*cdx.Vulnerabilities))

	matches := new([]Match)

	for _, v := range *cdx.Vulnerabilities {
		if len(*matches) == 0 {
			match := new(Match)
			match.Vulnerabilities = append(match.Vulnerabilities, &v)
			*matches = append(*matches, *match)
		} else {
			match := findMatch(&v, matches)
			if match != nil {
				match.Vulnerabilities = append(match.Vulnerabilities, &v)
			} else {
				match := new(Match)
				match.Vulnerabilities = append(match.Vulnerabilities, &v)
				*matches = append(*matches, *match)
			}
		}
	}

}

func CheckTally(vuln *[]cyclonedx.Vulnerability) *Tally {
	if vuln == nil {
		return nil
	}

	if len(*vuln) == 0 {
		return nil
	}
	var t Tally
	for _, v := range *vuln {
		if v.Ratings == nil {
			t.Unknown++
			continue
		}
		if len(*v.Ratings) == 0 {
			t.Unknown++
			continue
		}
		for _, r := range *v.Ratings {
			switch r.Severity {
			case "NEGLIGIBLE":
				t.Negligible++
			case "LOW":
				t.Low++
			case "MEDIUM":
				t.Medium++
			case "HIGH":
				t.High++
			case "CRITICAL":
				t.Critical++
			default:
				t.Unknown++
			}
		}
	}
	return &t
}

func findMatch(vuln *cyclonedx.Vulnerability, matches *[]Match) *Match {
	for _, m := range *matches {
		for _, v := range m.Vulnerabilities {
			if vuln.BOMRef == v.BOMRef {
				return &m
			} else {
				break
			}
		}
	}
	return nil
}
