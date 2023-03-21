package parser

import (
	"strings"

	"github.com/carbonetes/jacked/internal/model"
)

// Identity vendor via type for os packages
func getOSVendor(p *model.Package) *model.Package {

	// As we expand our database, we will add more information for vendors each os packages
	if p.Type == "deb" {
		p.Vendor = "debian"
	}
	if p.Type == "apk" {
		p.Vendor = "alpine"
	}
	if p.Type == "rpm" {
		p.Vendor = "gnu"
	}
	if p.Type == "gem" {
		p.Vendor = "rubyonrails"
	}

	if p.Type == "java" {
		if strings.Contains(p.Name, "spring") {
			p.Vendor = "vmware"
		}
		if p.Name == "spring-core" {
			p.Keywords = append(p.Keywords, "spring_framework")
		}
	}

	return p
}
