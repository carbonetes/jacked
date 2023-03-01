package matcher

import (
	"errors"
	"regexp"
	"strings"

	"github.com/carbonetes/jacked/internal/model"

	"github.com/hashicorp/go-version"
)

// Checking package current version with vulnerable versions
func MatchVersion(pv string, fv *model.Vulnerability) (bool, error) {

	if fv == nil {
		return false, errors.New("invalid vulnerability argument")
	}

	if len(pv) == 0 {
		return false, errors.New("invalid package argument")
	}

	// Check if version is valid and can be parse for comparison
	valid, out := validateVersion(pv)
	if !valid {
		pv = out
	}

	// Check if package version is within list vulnerable versions
	if len(fv.VersionEquals) != 0 {
		for _, v := range fv.VersionEquals {
			valid, out := validateVersion(v)
			if !valid {
				v = out
			}
			v1, err := version.NewVersion(pv)
			if err != nil {
				return false, err
			}
			v2, err := version.NewVersion(v)
			if err != nil {
				return false, err
			}
			if v1.Equal(v2) {
				return true, nil
			}
		}
	}

	// Check if package version is within list vulnerable range
	if len(fv.VersionStartIncluding) != 0 {
		for _, v := range fv.VersionStartIncluding {
			valid, out := validateVersion(v)
			if !valid {
				v = out
			}
			v1, err := version.NewVersion(pv)
			if err != nil {
				return false, err
			}
			v2, err := version.NewVersion(v)
			if err != nil {
				return false, err
			}
			if v1.GreaterThanOrEqual(v2) && (len(fv.VersionEndIncluding) != 0 || len(fv.VersionEndExcluding) != 0) {
				if len(fv.VersionEndIncluding) != 0 {
					for _, v := range fv.VersionEndIncluding {
						valid, out := validateVersion(v)
						if !valid {
							v = out
						}
						v1, err := version.NewVersion(pv)
						if err != nil {
							return false, err
						}
						v2, err := version.NewVersion(v)
						if err != nil {
							return false, err
						}
						if v1.LessThanOrEqual(v2) {
							return true, nil
						}
					}
				}
				if len(fv.VersionEndExcluding) != 0 {
					for _, v := range fv.VersionEndExcluding {
						valid, out := validateVersion(v)
						if !valid {
							v = out
						}
						v1, err := version.NewVersion(pv)
						if err != nil {
							return false, nil
						}
						v2, err := version.NewVersion(v)
						if err != nil {
							return false, err
						}
						if v1.LessThan(v2) {
							return true, nil
						}
					}
				}
			}
		}
	}

	if len(fv.VersionStartExcluding) != 0 {
		for _, v := range fv.VersionStartExcluding {
			valid, out := validateVersion(v)
			if !valid {
				v = out
			}
			v1, err := version.NewVersion(pv)
			if err != nil {
				return false, err
			}
			v2, err := version.NewVersion(v)
			if err != nil {
				return false, err
			}
			if v1.GreaterThan(v2) && (len(fv.VersionEndIncluding) != 0 || len(fv.VersionEndExcluding) != 0) {
				if len(fv.VersionEndIncluding) != 0 {
					for _, v := range fv.VersionEndIncluding {
						valid, out := validateVersion(v)
						if !valid {
							v = out
						}
						v1, err := version.NewVersion(pv)
						if err != nil {
							return false, err
						}
						v2, err := version.NewVersion(v)
						if err != nil {
							return false, err
						}
						if v1.LessThanOrEqual(v2) {
							return true, nil
						}
					}
				}
				if len(fv.VersionEndExcluding) != 0 {
					for _, v := range fv.VersionEndExcluding {
						valid, out := validateVersion(v)
						if !valid {
							v = out
						}
						v1, err := version.NewVersion(pv)
						if err != nil {
							return false, err
						}
						v2, err := version.NewVersion(v)
						if err != nil {
							return false, err
						}
						if v1.LessThan(v2) {
							return true, nil
						}
					}
				}
			}
		}
	}

	if len(fv.VersionStartExcluding) == 0 && len(fv.VersionStartIncluding) == 0 && len(fv.VersionEndIncluding) != 0 {
		for _, v := range fv.VersionEndIncluding {
			valid, out := validateVersion(v)
			if !valid {
				v = out
			}
			v1, err := version.NewVersion(pv)
			if err != nil {
				return false, nil
			}
			v2, err := version.NewVersion(v)
			if err != nil {
				return false, err
			}
			if v1.LessThanOrEqual(v2) {
				return true, nil
			}
		}
	}

	if len(fv.VersionStartExcluding) == 0 && len(fv.VersionStartIncluding) == 0 && len(fv.VersionEndExcluding) != 0 {
		for _, v := range fv.VersionEndExcluding {
			valid, out := validateVersion(v)
			if !valid {
				v = out
			}
			v1, err := version.NewVersion(pv)
			if err != nil {
				return false, err
			}
			v2, err := version.NewVersion(v)
			if err != nil {
				return false, err
			}
			if v1.LessThan(v2) {
				return true, nil
			}
		}
	}

	return false, nil
}

// Attempt to rapair invalid version
func repair(v string) string {
	if strings.Contains(v, "_") {
		v = strings.ReplaceAll(v, "_", "-")
	}
	if strings.Contains(v, "+") {
		v = strings.ReplaceAll(v, "+", "-")
	}
	if strings.Contains(v, "~") {
		v = strings.ReplaceAll(v, "~", "-")
	}
	if strings.Contains(v, "dfsg") {
		v = strings.ReplaceAll(v, "dfsg.", "")
	}
	if strings.Contains(v, ":") {
		tmp := strings.Split(v, ":")
		if len(tmp) == 2 {
			v = tmp[1]
		}
	}

	pattern := regexp.MustCompile(`^(\d+:)?([0-9]+\.[0-9]+\.[0-9]+)(\..*)?$`)
	match := pattern.FindStringSubmatch(v)
	if len(match) > 2 {
		v = match[2]
	}

	return v
}

// Check if version is valid
func validateVersion(v string) (bool, string) {
	if _, err := version.NewVersion(v); err != nil {
		v = repair(v)
		return false, v
	}

	return true, v
}
