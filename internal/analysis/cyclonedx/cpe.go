package analysis

import (
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/facebookincubator/nvdtools/wfn"
)

// MatchCPE is a function that takes in a slice of Common Platform Enumeration (CPE) strings and a pointer to a `model.Criteria` object, and returns true if any CPE matches the criteria, false otherwise.
// Input: a slice of CPE strings, and a pointer to a `model.Criteria` object.
// Output: a boolean value indicating whether any CPE matched the criteria.
func MatchCPE(cpes []string, criteria *model.Criteria) bool {
	// Iterate over each CPE string in the input slice.
	for _, p := range cpes {
		// Parse the CPE string using the `UnbindFmtString()` method from the `wfn` package's API. If an error occurs during parsing, skip to the next CPE string.
		pcpe, err := wfn.UnbindFmtString(p)
		if err != nil {
			continue
		}

		// Iterate over each CPE string in the `CPES` field of the `criteria` object.
		for _, v := range criteria.CPES {
			// Parse the CPE string using the `UnbindFmtString()` method from the `wfn` package's API. If an error occurs during parsing, skip to the next CPE string.
			vcpe, err := wfn.UnbindFmtString(v)
			if err != nil {
				continue
			}

			// Compare the parsed CPE components for the current input and criteria CPEs. If they match, update the `Constraint` field of the `criteria` object to include the version constraint and return true.
			if pcpe.Vendor == vcpe.Vendor && pcpe.Product == vcpe.Product && pcpe.Version == vcpe.Version {
				criteria.Constraint = "= " + vcpe.Version
				return true
			}
		}
	}

	// If no CPEs matched the criteria, return false.
	return false
}
