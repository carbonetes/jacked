package parser

import (
	"github.com/package-url/packageurl-go"
	"golang.org/x/exp/slices"
)

// Parsing package url to locate upstream packages and as keywords
func parsePurl(keywords []string, p string) []string {
	if p == "" {
		return keywords
	}

	var upstream string
	purl, err := packageurl.FromString(p)
	if purl.Name == "" {
		return keywords
	}
	if err != nil {
		log.Fatalf("Error parsing package url: %v", err)
	}
	upstream = purl.Qualifiers.Map()["upstream"]
	if len(upstream) > 0 {
		if !slices.Contains(keywords, upstream) {
			keywords = append(keywords, upstream)
		}
	}
	return keywords
}
