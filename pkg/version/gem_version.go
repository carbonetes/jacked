package version

import (
	"regexp"
	"strings"

	hashicorp "github.com/hashicorp/go-version"
)

type GemVersion struct {
	raw             string
	semanticVersion *hashicorp.Version
}

func NewGemVersion(versionStr string) (*GemVersion, error) {
	// Check if the version string is empty
	if versionStr == "" {
		return nil, NoVersionError
	}

	// Normalize the version string
	versionStr = normalizeGemVersion(versionStr)

	semanticVersion, err := hashicorp.NewVersion(versionStr)
	if err != nil {
		return nil, err
	}

	return &GemVersion{
		raw:             versionStr,
		semanticVersion: semanticVersion,
	}, nil
}

func normalizeGemVersion(raw string) string {
    platforms := []string{
        "x86", "universal", "arm", "darwin", "java", "mingw32", "mswin32", "x64-mingw32", "x64-mswin64",
    }
    pattern := "-(" + strings.Join(platforms, "|") + ")"
    re := regexp.MustCompile(pattern)
    loc := re.FindStringIndex(raw)
    if loc != nil {
        return strings.TrimSpace(raw[:loc[0]])
    }
    return strings.TrimSpace(raw)
}
