package version

import (
	"fmt"
	"regexp"
	"strconv"
)

type apkVersion struct {
	raw             apkVersionRaw
	semanticVersion string
}

type apkVersionRaw struct {
	main    string
	sub     string
	release int
}

func NewApkVersion(version string) (v *apkVersion, err error) {
	raw, err := parseApkVersion(version)
	if err != nil {
		return nil, err
	}

	v = &apkVersion{raw: raw, semanticVersion: normalizeUpstreamVersion(raw.main)}
	return v, nil
}

func parseApkVersion(version string) (apkVersionRaw, error) {
	// Regex: major.minor(.patch)?-r<release>(rest)?
	re := regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?-r(\d+)(.*)?$`)
	m := re.FindStringSubmatch(version)
	if m == nil {
		return apkVersionRaw{}, fmt.Errorf("invalid alpine version format: %s", version)
	}

	major, _ := strconv.Atoi(m[1])
	minor := 0
	patch := 0
	if m[2] != "" {
		minor, _ = strconv.Atoi(m[2])
	}
	if m[3] != "" {
		patch, _ = strconv.Atoi(m[3])
	}
	release, _ := strconv.Atoi(m[4])
	rest := m[5]

	// Always output semver as "major.minor.patch"
	semver := fmt.Sprintf("%d.%d.%d", major, minor, patch)

	return apkVersionRaw{
		main:  semver,
		release: release,
		sub:    rest,
	}, nil
}
