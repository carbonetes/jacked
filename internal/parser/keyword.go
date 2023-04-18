package parser

import (
	"strings"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/pkg/core/model"

	"golang.org/x/exp/slices"
)

// Collection of common keywords that cannot be used on each package
var excluded = []string{"cli", "v2", "net", "crypto", "sync"}

// Read each package, collect all licenses and create a list of keywords for each package
func ParsePackages(pkgs *[]model.Package, licenses *[]model.License, cfg *config.Configuration) {
	for index, p := range *pkgs {
		tmp := *pkgs
		if cfg.LicenseFinder {
			lcn := *licenses
			lcn = append(lcn, getLicense(&p)...)
			*licenses = lcn
		}
		tmp[index] = *getOSVendor(&p)
		tmp[index] = CreateKeywords(tmp[index])
		*pkgs = tmp
	}
}

// Create keywords for each package to be used matching with potential vulnerabilities
func CreateKeywords(pkg model.Package) model.Package {
	var keywords []string

	switch pkg.Type {
	case "java":
		pkg = *parseJavaMetadata(&pkg)
	case "go-module":
		keywords = createGoKeywords(keywords, pkg.Name)
	case "deb":
		keywords = parseDebianMetadata(&pkg, keywords)
	case "apk":
		keywords = parseAlpineMetadata(&pkg, keywords)
	case "rpm":
		keywords = parseRpmMetadata(&pkg, keywords)
	//more parsers
	default:
		// default
	}

	if len(pkg.CPEs) > 0 {
		for _, c := range pkg.CPEs {
			parts := strings.Split(c, ":")
			if !slices.Contains(keywords, parts[4]) {
				keywords = append(keywords, parts[4])
			}
		}
	}

	keywords = checkDelimeters(keywords)
	keywords = removeExcluded(keywords)
	pkg.Keywords = append(pkg.Keywords, keywords...)
	pkg.Keywords = append(pkg.Keywords, pkg.Name)

	return pkg
}

func checkDelimeters(keywords []string) []string {
	for _, k := range keywords {
		if strings.Contains(k, "-") {
			keyword := strings.ReplaceAll(k, "-", "_")
			if !slices.Contains(keywords, keyword) {
				keywords = append(keywords, keyword)
			}
		}
		if strings.Contains(k, "_") {
			keyword := strings.ReplaceAll(k, "_", "-")
			if !slices.Contains(keywords, keyword) {
				keywords = append(keywords, keyword)
			}
		}
	}
	return keywords
}

// Filter out keywords that cannot be used
func removeExcluded(keywords []string) []string {
	for index, k := range keywords {
		for _, e := range excluded {
			if k == e {
				keywords = append(keywords[:index], keywords[index+1:]...)
			}
		}

	}
	return keywords
}
