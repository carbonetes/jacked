package parser

import (
	"strings"

	"golang.org/x/exp/slices"
)

// Parse go module and returns package name
func parseGoPkg(pkg string) string {
	s := strings.Split(pkg, "/")
	if len(s) >= 3 {
		return s[2]
	} else {
		return s[len(s)-1]
	}

}
// Create keywords based on the package name
func createGoKeywords(keywords []string, s string) []string {
	keyword := parseGoPkg(s)
	if !slices.Contains(keywords, keyword) {
		keywords = append(keywords, keyword)
	}
	return keywords
}
