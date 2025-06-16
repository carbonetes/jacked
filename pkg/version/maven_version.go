package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type mavenVersion struct {
	raw             mavenVersionRaw
	semanticVersion string
}

type mavenVersionRaw struct {
	Major     int
	Minor     int
	Patch     int
	Qualifier string
	Snapshot  bool
	Timestamp string
	BuildNum  int
	Raw       string
}

func NewMavenVersion(version string) (*mavenVersion, error) {
	raw, err := parseMavenVersion(version)
	if err != nil {
		return nil, err
	}

	v := &mavenVersion{
		raw:             raw,
		semanticVersion: normalizeMavenVersion(raw),
	}
	return v, nil
}

func parseMavenVersion(version string) (raw mavenVersionRaw, err error) {
	// Regex for: 1.2.3-QUALIFIER, 1.2.3, 1.2, 1.2.3-YYYYMMDD.HHMMSS-N, etc.
	re := regexp.MustCompile(`^(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([A-Za-z0-9\.]+))?(?:-([0-9]{8}\.[0-9]{6})-(\d+))?$`)
	matches := re.FindStringSubmatch(version)
	if matches == nil || len(matches) < 4 {
		return mavenVersionRaw{}, fmt.Errorf("invalid maven version: %s", version)
	}

	raw.Major, _ = strconv.Atoi(matches[1])
	raw.Minor = 0
	raw.Patch = 0
	if matches[2] != "" {
		raw.Minor, _ = strconv.Atoi(matches[2])
	}
	if matches[3] != "" {
		raw.Patch, _ = strconv.Atoi(matches[3])
	}

	if matches[4] != "" {
		raw.Qualifier = strings.ToUpper(matches[4])
		if raw.Qualifier == "SNAPSHOT" {
			raw.Snapshot = true
		}
	}

	if matches[5] != "" {
		raw.Timestamp = matches[5]
	}
	if matches[6] != "" {
		raw.BuildNum, _ = strconv.Atoi(matches[6])
	}

	return raw, nil
}

func normalizeMavenVersion(raw mavenVersionRaw) string {
	// parse symantic version from raw components
	return fmt.Sprintf("%d.%d.%d", raw.Major, raw.Minor, raw.Patch)
}
