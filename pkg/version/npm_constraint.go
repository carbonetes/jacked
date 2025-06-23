package version

import npm "github.com/aquasecurity/go-npm-version/pkg"

func (v *NpmVersion) Check(constraints string) (bool, error) {
	c, err := npm.NewConstraints(constraints)
	if err != nil {
		return false, err
	}

	return c.Check(v.npmVer), nil
}
