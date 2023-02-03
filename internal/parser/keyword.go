package parser

import (
	"strings"

	"github.com/carbonetes/jacked/internal/config"
	"github.com/carbonetes/jacked/internal/model"

	"github.com/facebookincubator/nvdtools/wfn"
	"golang.org/x/exp/slices"

	prmt "github.com/gitchander/permutation"
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
	if len(pkg.PURL) > 0 {
		keywords = parsePurl(keywords, string(pkg.PURL))
	}
	pkg.Keywords = append(pkg.Keywords, keywords...)
	pkg = *addCPEs(&pkg)
	return pkg
}

func checkDelimeters(keywords []string) []string {
	for _, k := range keywords {
		if strings.Contains(k, "-") {
			keyword := strings.ReplaceAll(k, "-", "_")
			if !slices.Contains(keywords, keyword) {
				keywords = append(keywords, keyword)
			}
			k = strings.ReplaceAll(k, "_", "-")
			parts := strings.Split(k, "-")
			keywords = shuffleKeywordParts(parts, keywords, "-")
			if len(parts) > 2 {
				parts = parts[:len(parts)-1]
				keyword = strings.Join(parts, "-")
				if !slices.Contains(keywords, keyword) {
					keywords = append(keywords, strings.Join(parts, "-"))
				}
				keywords = shuffleKeywordParts(parts, keywords, "-")
			}
		}
		if strings.Contains(k, "_") {
			keyword := strings.ReplaceAll(k, "_", "-")
			if !slices.Contains(keywords, keyword) {
				keywords = append(keywords, keyword)
			}
			k = strings.ReplaceAll(k, "-", "_")
			parts := strings.Split(k, "_")
			// keywords = shuffleKeywordParts(parts, keywords, "_")
			if len(parts) > 2 {
				parts = parts[:len(parts)-1]
				keyword = strings.Join(parts, "_")
				if !slices.Contains(keywords, keyword) {
					keywords = append(keywords, keyword)
				}
				// keywords = shuffleKeywordParts(parts, keywords, "_")
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

// Create a new set of keywords by shuffling the parts a the string
func shuffleKeywordParts(parts, keywords []string, separator string) []string {
	if len(parts) > 0 {
		result := prmt.New(prmt.StringSlice(parts))
		for result.Next() {
			newKeyword := strings.Join(parts, separator)
			if !slices.Contains(keywords, newKeyword) {
				keywords = append(keywords, newKeyword)
			}
		}
	}
	return keywords
}

// Generate new set of cpes based on the set vendor and keywords
func addCPEs(pkg *model.Package) *model.Package {
	if len(pkg.Keywords) == 0 {
		return pkg
	}

	var vendors []string
	if len(pkg.CPEs) > 0 {
		for _, c := range pkg.CPEs {
			cpe, err := wfn.UnbindFmtString(c)
			if err != nil {
				log.Errorln(err.Error())
			}
			if cpe.Product != cpe.Vendor {
				vendors = append(vendors, cpe.Vendor)
			}
		}
	}

	for _, keyword := range pkg.Keywords {
		newCpe, err := wfn.UnbindFmtString("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
		if err != nil {
			log.Errorln(err.Error())
		}
		if len(pkg.Vendor) > 0 {
			newCpe.Vendor = pkg.Vendor
			newCpe.Product = keyword
			newCpe.Version = pkg.Version
			if !slices.Contains(pkg.CPEs, newCpe.BindToFmtString()) {
				pkg.CPEs = append(pkg.CPEs, newCpe.BindToFmtString())
			}
		}
		newCpe.Vendor = keyword
		newCpe.Product = keyword
		newCpe.Version = pkg.Version
		if !slices.Contains(pkg.CPEs, newCpe.BindToFmtString()) {
			pkg.CPEs = append(pkg.CPEs, newCpe.BindToFmtString())
		}

		if len(vendors) > 0 {
			for _, vendor := range vendors {
				newCpe.Product = keyword
				newCpe.Vendor = vendor
				newCpe.Version = pkg.Version
				if !slices.Contains(pkg.CPEs, newCpe.BindToFmtString()) {
					pkg.CPEs = append(pkg.CPEs, newCpe.BindToFmtString())
				}
			}
		}
	}
	return pkg
}
