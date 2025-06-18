package version

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/carbonetes/jacked/internal/helper"
	hashicorp "github.com/hashicorp/go-version"
)

type JVMVersion struct {
	raw             string
	semanticVersion *hashicorp.Version
	isJEP223        bool
}

var (
	semverishPattern = regexp.MustCompile(`(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:-(?P<prerelease>[0-9A-Za-z-]+))?(?:\+(?P<build>[0-9A-Za-z-]+))?`)
	preJep223Pattern = regexp.MustCompile(`(?P<major>\d+)\.(?P<minor>\d+)\.(?P<patch>\d+)(?:_(?P<prerelease>[0-9A-Za-z-]+))?(?:-(?P<build>[0-9A-Za-z-]+))?`)
)

func NewJVMVersion(versionStr string) (*JVMVersion, error) {
	isJep223 := isJEP223(versionStr)
	var normalized string
	if isJep223 {
		normalized = normalizeSemverish(versionStr)
	} else {
		normalized = normalizePreJep223(versionStr)
	}
	verObj, err := hashicorp.NewVersion(normalized)
	if err != nil {
		return nil, fmt.Errorf("unable to create semver obj for JVM version: %w", err)
	}
	return &JVMVersion{
		raw:             versionStr,
		semanticVersion: verObj,
		isJEP223:        isJep223,
	}, nil
}

func isJEP223(versionStr string) bool {
	return strings.HasPrefix(versionStr, "1.")
}

// --- Normalization helpers ---

func normalizeSemverish(version string) string {
	matches := helper.MatchNamedCaptureGroups(semverishPattern, version)
	if len(matches) == 0 {
		// log trace removed for simplicity
		return version
	}
	major := trimLeftZeros(matches["major"])
	minor := trimLeftZeros(matches["minor"])
	patch := trimLeftZeros(matches["patch"])
	update := trimLeftZeros(matches["update"])
	pre := trimLeftZeros(matches["prerelease"])
	build := trimLeftZeros(matches["build"])

	if (patch == "" || patch == "0") && update != "" {
		patch = update
	}
	return buildSemVer(major, minor, patch, pre, build)
}

func buildSemVer(major, minor, patch, pre, build string) string {
	if minor == "" {
		minor = "0"
	}
	segs := []string{major, minor}
	if patch != "" {
		segs = append(segs, patch)
	}
	var sb strings.Builder
	sb.WriteString(strings.Join(segs, "."))
	if pre != "" {
		sb.WriteString("-" + pre)
	}
	if build != "" {
		sb.WriteString("+" + build)
	}
	return sb.String()
}

func trimLeftZeros(v string) string {
	if v == "0" {
		return v
	}
	return strings.TrimLeft(v, "0")
}

func normalizePreJep223(version string) string {
	matches := helper.MatchNamedCaptureGroups(preJep223Pattern, version)
	if len(matches) == 0 {
		// log trace removed for simplicity
		return version
	}
	major := trimLeftZeros(matches["major"])
	minor := trimLeftZeros(matches["minor"])
	patch := trimLeftZeros(matches["patch"])
	pre := trimLeftZeros(matches["prerelease"])
	build := trimLeftZeros(matches["build"])

	return buildSemVer(major, minor, patch, pre, build)
}
