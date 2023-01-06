package matcher

import "github.com/carbonetes/jacked/internal/model"

func matchCriteria(pkg *model.Package, vuln *model.Vulnerability) bool {

	//check package vendor, keyword patterns and package name if matched with vulnerability
	if pkg.Vendor != "" {
		if pkg.Vendor == vuln.Vendor {
			if pkg.Name == vuln.Package {
				return true
			}
			for _, k := range pkg.Keywords {
				if k == vuln.Package {
					return true
				}
			}
		}
	}

	return false
}
