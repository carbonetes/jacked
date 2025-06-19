package version

import (
	"fmt"

	apk "github.com/knqyf263/go-apk-version"
)

type apkVersion struct {
	raw    string
	apkVer *apk.Version
}

func NewApkVersion(v string) (*apkVersion, error) {
	if len(v) == 0 {
		return nil, fmt.Errorf("version is empty")
	}

	// Parse the normalized version using go-apk-version
	ver, err := apk.NewVersion(v)
	if err != nil {
		return nil, fmt.Errorf("failed to parse apk version: %w", err)
	}

	return &apkVersion{
		raw:    v,
		apkVer: &ver,
	}, nil
}
