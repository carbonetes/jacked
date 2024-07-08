package compare

import "github.com/facebookincubator/nvdtools/wfn"

func MatchCPE(componentCPE string, vulnCPEs []string) (bool, string) {

	pcpe, err := wfn.UnbindFmtString(componentCPE)
	if err != nil {
		return false, ""
	}

	for _, v := range vulnCPEs {

		vcpe, err := wfn.UnbindFmtString(v)
		if err != nil {
			continue
		}

		if pcpe.Vendor == vcpe.Vendor && pcpe.Product == vcpe.Product && pcpe.Version == vcpe.Version {
			return true, v
		}
	}

	return false, ""
}
