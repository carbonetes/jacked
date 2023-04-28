package spinner

import (
	"os"
	"strconv"
)

func OnCheckDatabaseUpdateStart() {
	SetMessage("Checking Database Update")
	Start()
}

func OnDatabaseUpdateStart() {
	SetMessage("Database Updated")
	Stop()
}

func OnSBOMScan(img string) {
	SetMessage("Searching for Packages [" + img + "]")
	Start()

}

func OnVulnAnalysisStart(pkg int) {
	SetMessage("Scanning for vulnerabilities [" + strconv.Itoa(pkg) + " packages]")
	Start()
}

func OnPause() {
	err := spin.Pause()
	if err != nil {
		log.Errorln(err.Error())
	}
}
func OnStop(err error) {
	if err != nil {
		spin.StopFailMessage("\n" + err.Error())
		StopFail()
		os.Exit(1)
	}
	Stop()
}
