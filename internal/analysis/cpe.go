package analysis

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/facebookincubator/nvdtools/wfn"
)

// MatchCPE function matches the CPEs of a package with the given criteria.
func MatchCPE(pkg *dm.Package, criteria *model.Criteria) bool {
	// Loop through all the CPEs of the package.
	for _, p := range pkg.CPEs {
		// Get Package CPE from formatted string
		pcpe, err := wfn.UnbindFmtString(p)
		if err != nil {
			continue
		}

		// If the version is 'ANY', continue to the next iteration.
		if pcpe.Version == wfn.Any {
			continue
		}
		// Check if the CPE matches the criteria.
		matched := matchCPE(criteria, pcpe)
		if matched {
			return true
		}
	}
	return false
}

// matchCPE function matches the given CPE with the criteria.
func matchCPE(criteria *model.Criteria, pcpe *wfn.Attributes) bool {
	// Loop through all the CPEs in the criteria.
	for _, v := range criteria.CPES {
		// Get Vulnerability Criteria CPE from formatted string
		vcpe, err := wfn.UnbindFmtString(v)
		if err != nil {
			continue
		}

		// If the version is 'ANY', continue to the next iteration.
		if vcpe.Version == wfn.Any {
			continue
		}

		// If the vendor, product and version match, set the constraint and return true.
		if pcpe.Vendor == vcpe.Vendor && pcpe.Product == vcpe.Product && pcpe.Version == vcpe.Version {
			criteria.Constraint = "= " + vcpe.Version
			return true
		}
	}
	return false
}
