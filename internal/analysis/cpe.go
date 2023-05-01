package analysis

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/facebookincubator/nvdtools/wfn"
)

func MatchCPE(pkg *dm.Package, criteria *model.Criteria) bool {

	for _, p := range pkg.CPEs {
		pcpe, err := wfn.UnbindFmtString(p)
		if err != nil {
			continue
		}

		if pcpe.Version == wfn.Any {
			continue
		}

		for _, v := range criteria.CPES {
			vcpe, err := wfn.UnbindFmtString(v)
			if err != nil {
				continue
			}

			if vcpe.Version == wfn.Any {
				continue
			}

			if pcpe.Vendor == vcpe.Vendor && pcpe.Product == vcpe.Product && pcpe.Version == vcpe.Version {
				criteria.Constraint = "= " + vcpe.Version
				return true
			}
		}
	}

	return false
}
