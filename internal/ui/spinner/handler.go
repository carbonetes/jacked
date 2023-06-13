package spinner

import (
	"os"
	"strconv"
)

func OnCheckDatabaseStart() {
	if disable {
		return
	}
	SetMessage("Checking Database")
	Start()
}

func OnDatabaseUpdateStart() {
	if disable {
		return
	}
	SetMessage("Database Updated")
}

func OnSBOMScan(img string) {
	if disable {
		return
	}
	SetMessage("Searching for Packages [" + img + "]")
	Start()

}

func OnVulnAnalysisStart(pkg int) {
	if disable {
		return
	}
	SetMessage("Scanning for vulnerabilities [" + strconv.Itoa(pkg) + " packages]")
	Start()
}

func OnPause() {
	if disable {
		return
	}
	err := spin.Pause()
	if err != nil {
		log.Errorln(err.Error())
	}
}
func OnStop(err error) {
	if disable {
		return
	}
	if err != nil {
		spin.StopFailMessage("\n" + err.Error())
		StopFail()
		os.Exit(1)
	}
	Stop()
}
