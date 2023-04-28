package sbom

import (
	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/pkg/core/model"
)

func GetLicense(pkgs *[]dm.Package, licenses *[]model.License) {
	for _, pkg := range *pkgs {
		if len(pkg.Licenses) > 0 {
			for _, license := range pkg.Licenses {
				var license = model.License{
					Package: pkg.Name,
					License: license,
				}
				*licenses = append(*licenses, license)
			}
		}
	}
}
