package analysis

import "github.com/facebookincubator/nvdtools/wfn"

func MatchCPE(pcpe, vcpe []string) (bool, string) {
	for _, p := range pcpe {
		pp, err := wfn.UnbindFmtString(p)
		if err != nil {
			continue
		}

		for _, v := range vcpe {
			vv, err := wfn.UnbindFmtString(v)
			if err != nil {
				continue
			}

			if pp.Vendor == vv.Vendor && pp.Product == vv.Product && pp.Version == vv.Version {
				return true, v
			}
		}
	}

	return false, ""
}
