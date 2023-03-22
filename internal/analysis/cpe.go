package analysis

import (
	"strings"

	"github.com/carbonetes/jacked/internal/model"
	"github.com/facebookincubator/nvdtools/wfn"
)

func MatchCPE(pkg *model.Package, criteria *model.Criteria) bool {

	for _, p := range pkg.CPEs {
		pcpe, err := wfn.UnbindFmtString(p)
		if err != nil {
			continue
		}

		for _, v := range criteria.CPES {
			vcpe, err := wfn.UnbindFmtString(v)
			if err != nil {
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

func checkProductVendor(pkg *model.Package, vulnerability *model.Vulnerability) bool {

	if len(vulnerability.Criteria.CPES) > 0 {
		for _, v := range vulnerability.Criteria.CPES {
			vcpe, err := wfn.UnbindFmtString(v)
			if err != nil {
				continue
			}

			for _, keyword := range pkg.Keywords {
				if strings.EqualFold(cleanString(vcpe.Product), keyword) {
					return true
				}
			}
		}
	}

	return false
}

func cleanString(s string) string {
	if strings.Contains(s, "\\") {
		r := strings.Replace(s, "\\", "", -1)
		return r
	}
	return s
}
