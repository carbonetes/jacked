package sbom

import (
	"strings"

	dm "github.com/carbonetes/diggity/pkg/model"
	"github.com/carbonetes/jacked/internal/sbom/metadata"
	"github.com/carbonetes/jacked/pkg/core/model"
	"github.com/facebookincubator/nvdtools/wfn"
	"golang.org/x/exp/slices"
)

func Inspect(pkgs *[]dm.Package, signatures *map[string]model.Signature) {
	for _, p := range *pkgs {
		var signature model.Signature
		if len(p.CPEs) > 0 {
			for _, c := range p.CPEs {
				cpe, err := wfn.UnbindFmtString(c)
				if err != nil {
					continue
				}
				product := cleanString(cpe.Product)
				if !slices.Contains(signature.Keywords, product) {
					signature.Keywords = append(signature.Keywords, product)
				}
			}
		}
		switch p.Type {
		case "java":
			metadata.ParseJavaMetadata(&p, &signature)
		case "deb":
			metadata.ParseDebianMetadata(&p, &signature)
		case "rpm":
			metadata.ParseRpmMetadata(&p, &signature)
		case "apk":
			metadata.ParseAlpineMetadata(&p, &signature)
		}
		if p.Type == "deb" {
			signature.Vendor = append(signature.Vendor, "debian")
		}
		if p.Type == "apk" {
			signature.Vendor = append(signature.Vendor, "alpine")
		}
		if p.Type == "rpm" {
			signature.Vendor = append(signature.Vendor, "gnu")
		}
		if p.Type == "gem" {
			signature.Vendor = append(signature.Vendor, "rubyonrails")
		}
		(*signatures)[p.ID] = signature
	}
}

func cleanString(s string) string {
	if strings.Contains(s, "\\") {
		r := strings.Replace(s, "\\", "", -1)
		return r
	}
	return s
}
