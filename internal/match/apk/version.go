package apk

import (
	"errors"
	"unicode"
)

// Version represents a package version.
type Version string

// Constants for version comparison results.
const (
	apkVersionEqual   = 0
	apkVersionLess    = -1
	apkVersionGreater = 1
)

// Predefined suffixes for version comparison.
var (
	preSuffixes  = []string{"alpha", "beta", "pre", "rc"}
	postSuffixes = []string{"cvs", "svn", "git", "hg", "p"}
)

// NewVersion validates and returns a new Version instance.
func NewVersion(ver string) (Version, error) {
	if !Valid(ver) {
		return Version(ver), errors.New("invalid version")
	}
	return Version(ver), nil
}

// Valid checks if the version string is valid.
func Valid(ver string) bool {
	return parseVersion(ver) != nil
}

// Equal checks if two versions are equal.
func (v Version) Equal(v2 Version) bool {
	return v.Compare(v2) == apkVersionEqual
}

// GreaterThan checks if the version is greater than another version.
func (v Version) GreaterThan(v2 Version) bool {
	return v.Compare(v2) == apkVersionGreater
}

// LessThan checks if the version is less than another version.
func (v Version) LessThan(v2 Version) bool {
	return v.Compare(v2) == apkVersionLess
}

// Compare compares two versions.
func (v Version) Compare(v2 Version) int {
	return compareVersions(string(v), string(v2))
}

// compareVersions compares two version strings.
func compareVersions(v1, v2 string) int {
	p1, p2 := parseVersion(v1), parseVersion(v2)
	for i := 0; i < len(p1) && i < len(p2); i++ {
		if p1[i] < p2[i] {
			return apkVersionLess
		} else if p1[i] > p2[i] {
			return apkVersionGreater
		}
	}
	if len(p1) < len(p2) {
		return apkVersionLess
	} else if len(p1) > len(p2) {
		return apkVersionGreater
	}
	return apkVersionEqual
}

// parseVersion parses a version string into a slice of integers for comparison.
func parseVersion(ver string) []int {
	var result []int
	var num int
	var hasNum bool
	for _, r := range ver {
		if unicode.IsDigit(r) {
			num = num*10 + int(r-'0')
			hasNum = true
		} else {
			if hasNum {
				result = append(result, num)
				num = 0
				hasNum = false
			}
			if idx := indexInSlices(string(r), preSuffixes, postSuffixes); idx != 0 {
				result = append(result, idx)
			}
		}
	}
	if hasNum {
		result = append(result, num)
	}
	return result
}

// indexInSlices checks if a string is in any of the given slices and returns a unique index.
func indexInSlices(s string, slices ...[]string) int {
	for _, slice := range slices {
		for i, item := range slice {
			if s == item {
				return i + 1 // Ensure non-zero index
			}
		}
	}
	return 0
}
