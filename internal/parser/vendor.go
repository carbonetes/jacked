package parser

import (
	"github.com/carbonetes/jacked/internal/model"
)

// Identity vendor via type for os packages
func getOSVendor(p *model.Package) *model.Package {

	// As we expand our database, we will add more information for vendors each os packages
	if p.Type == "deb" {
		p.Vendor = "Debian"
	}
	if p.Type == "apk" {
		p.Vendor = "Alpine Linux"
	}
	if p.Type == "rpm" {
		p.Vendor = "gnu"
	}
	if p.Type == "gem" {
		p.Vendor = "rubyonrails"
	}

	return p
}
