package debian

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// Version structure to hold the parsed version information.
type Version struct {
	Epoch           int
	UpstreamVersion string
	DebianRevision  string
}

const (
	debianVersionEqual   = 0
	debianVersionLess    = -1
	debianVersionGreater = 1
)

// NewVersion parses the given version string and returns a Version object.
func NewVersion(versionStr string) (*Version, error) {
	versionStr = strings.TrimSpace(versionStr)

	var epoch int
	var err error
	parts := strings.SplitN(versionStr, ":", 2)
	if len(parts) == 2 {
		epoch, err = strconv.Atoi(parts[0])
		if err != nil {
			return nil, fmt.Errorf("invalid epoch: %w", err)
		}
		if epoch < 0 {
			return nil, errors.New("epoch cannot be negative")
		}
		versionStr = parts[1]
	}

	upstreamVersion, debianRevision := splitVersion(versionStr)

	if err := validateUpstreamVersion(upstreamVersion); err != nil {
		return nil, err
	}

	if err := validateDebianRevision(debianRevision); err != nil {
		return nil, err
	}

	return &Version{
		Epoch:           epoch,
		UpstreamVersion: upstreamVersion,
		DebianRevision:  debianRevision,
	}, nil
}

// splitVersion splits the version string into upstream version and debian revision.
func splitVersion(versionStr string) (string, string) {
	parts := strings.Split(versionStr, "-")
	if len(parts) > 1 {
		return strings.Join(parts[:len(parts)-1], "-"), parts[len(parts)-1]
	}
	return versionStr, ""
}

// validateUpstreamVersion checks if the upstream version is valid.
func validateUpstreamVersion(version string) error {
	if version == "" {
		return errors.New("upstream version cannot be empty")
	}
	if !unicode.IsDigit(rune(version[0])) {
		return errors.New("upstream version must start with a digit")
	}
	for _, char := range version {
		if !unicode.IsDigit(char) && !unicode.IsLetter(char) && !strings.ContainsRune(".+-:~", char) {
			return fmt.Errorf("invalid character '%c' in upstream version", char)
		}
	}
	return nil
}

// validateDebianRevision checks if the debian revision is valid.
func validateDebianRevision(revision string) error {
	for _, char := range revision {
		if !unicode.IsDigit(char) && !unicode.IsLetter(char) && !strings.ContainsRune("+.~", char) {
			return fmt.Errorf("invalid character '%c' in debian revision", char)
		}
	}
	return nil
}

// Compare compares two versions and returns an integer indicating the relationship.
// Returns 0 if v == other, -1 if v < other, and 1 if v > other.
func (v *Version) Compare(other *Version) int {
	if v.Epoch != other.Epoch {
		return compareInts(v.Epoch, other.Epoch)
	}

	upstreamComparison := compareVersions(v.UpstreamVersion, other.UpstreamVersion)
	if upstreamComparison != 0 {
		return upstreamComparison
	}

	return compareVersions(v.DebianRevision, other.DebianRevision)
}

// compareInts compares two integers and returns -1, 0, or 1.
func compareInts(a, b int) int {
	if a < b {
		return -1
	} else if a > b {
		return 1
	}
	return 0
}

// compareVersions compares two version strings.
func compareVersions(a, b string) int {
	if a == b {
		return 0
	}

	aParts, bParts := splitVersionParts(a), splitVersionParts(b)
	for i := 0; i < len(aParts) || i < len(bParts); i++ {
		if i >= len(aParts) {
			return -1
		}
		if i >= len(bParts) {
			return 1
		}

		if aParts[i] != bParts[i] {
			if isNumeric(aParts[i]) && isNumeric(bParts[i]) {
				aNum, _ := strconv.Atoi(aParts[i])
				bNum, _ := strconv.Atoi(bParts[i])
				return compareInts(aNum, bNum)
			}
			return strings.Compare(aParts[i], bParts[i])
		}
	}

	return 0
}

// splitVersionParts splits a version into numeric and non-numeric parts.
func splitVersionParts(version string) []string {
	return regexp.MustCompile(`(\d+|\D+)`).FindAllString(version, -1)
}

// isNumeric checks if a string is numeric.
func isNumeric(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}
