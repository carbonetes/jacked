package parser

import "github.com/carbonetes/jacked/internal/model"

// Compile all license found on each package
func getLicense(pkg *model.Package) []model.License {
	var licenses []model.License
	if len(pkg.Licenses) > 0 {
		for _, license := range pkg.Licenses {
			var license = model.License{
				Package: pkg.Name,
				License: license,
			}
			licenses = append(licenses, license)
		}
	}
	return licenses
}
