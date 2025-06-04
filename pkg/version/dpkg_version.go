package version

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type dpkgVersion struct {
	raw             dpkgVersionRaw
	semanticVersion string
}

// Raw format of the dpkg version [epoch:]upstream-version[-debian-revision]
type dpkgVersionRaw struct {
	epoch    int
	upstream string
	revision string
}

func NewDpkgVersion(version string) (v *dpkgVersion, err error) {
	raw, err := parseDpkgVersion(version)
	if err != nil {
		return nil, err
	}

	v = &dpkgVersion{raw: raw, semanticVersion: normalizeUpstreamVersion(raw.upstream)}
	return v, nil
}

func parseDpkgVersion(version string) (raw dpkgVersionRaw, err error) {
	// Updated regex to include binNMU suffix (e.g., +b1)
	re := regexp.MustCompile(`(?:(\d+):)?([^:-]+)(?:-([^+]+(?:\+b\d+)?))?`)

	matches := re.FindStringSubmatch(version)
	if len(matches) == 0 {
		return dpkgVersionRaw{}, fmt.Errorf("invalid dpkg version: %s", version)
	}
	// Parse epoch (if present)
	if matches[1] != "" {
		raw.epoch, err = strconv.Atoi(matches[1])
		if err != nil {
			return raw, fmt.Errorf("invalid epoch: %v", err)
		}
	}

	// Assign upstream version
	raw.upstream = matches[2]

	// Assign Debian revision (if present)
	if matches[3] != "" {
		raw.revision = matches[3]
	}

	return raw, nil
}

func normalizeUpstreamVersion(upstream string) string {
	// Remove any Debian-specific suffixes (e.g., ~, +, etc.)
	clean := regexp.MustCompile(`[^\d\.]`).ReplaceAllString(upstream, ".")
	// Remove alphanumeric characters
	clean = regexp.MustCompile(`[a-zA-Z]`).ReplaceAllString(clean, "")
	// Remove trailing dot if present
	clean = strings.TrimSuffix(clean, ".")

	parts := strings.Split(clean, ".")
	semver := []string{"0", "0", "0"}

	for i := 0; i < 3 && i < len(parts); i++ {
		if parts[i] != "" {
			semver[i] = parts[i]
		}
	}
	return strings.Join(semver, ".")
}
