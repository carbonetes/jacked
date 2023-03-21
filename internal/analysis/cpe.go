package analysis

import (
	"strings"

	"github.com/carbonetes/jacked/internal/model"
	"github.com/facebookincubator/nvdtools/wfn"
)

func MatchCPE(pkg *model.Package, criteria *model.Criteria) (bool, *wfn.Attributes) {
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
				return true, vcpe
			}
		}
	}

	return false, nil
}

func CheckProductVendor(pkg *model.Package, criteria *model.Criteria, pkgName string) bool {
	if len(criteria.CPES) > 0 {
		for _, v := range criteria.CPES {
			vcpe, err := wfn.UnbindFmtString(v)
			if err != nil {
				continue
			}

			if strings.EqualFold(CleanString(vcpe.Product), pkg.Name) {
				return true
			}
		}
	}

	if strings.EqualFold(criteria.Source, "ghsa") && len(pkgName) > 0 {
		if strings.EqualFold(criteria.Scope, "maven") && strings.EqualFold(pkg.Type, "java") {
			if strings.Contains(pkgName, pkg.Name) {
				return true
			}
		}
	}

	return false
}

func CleanString(s string) string {
	if strings.Contains(s, "\\") {
		r := strings.Replace(s, "\\", "", -1)
		return r
	}
	return s
}
