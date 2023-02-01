package matcher

import (
	"github.com/facebookincubator/nvdtools/wfn"
)

type CPE = wfn.Attributes

// Match package cpes with vulnerability cpes
func MatchCpe(p []string, v string) (bool, error) {

	if len(p) == 0 || len(v) == 0 {
		//return false, errors.New("invalid arguments")
		return false, nil
	}

	vcpe, err := wfn.UnbindFmtString(v)

	if err != nil {
		return false, err
	}

	for _, p := range p {
		pcpe, err := wfn.UnbindFmtString(p)
		if err != nil {
			log.Errorln(err.Error())
		}
		if match(pcpe, vcpe) {
			return true, nil
		}
	}

	return false, nil
}

func match(cpe1 *CPE, cpe2 *CPE) bool {

	/*
		We do not support checking for like part and update values yet but we will definitely implement thorough on cpes
	*/

	if cpe1.Vendor != cpe2.Vendor {
		return false
	}

	if cpe1.Product != cpe2.Product {
		return false
	}

	return true
}
