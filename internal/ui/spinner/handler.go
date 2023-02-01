package spinner

import "strconv"

func OnCheckDatabaseUpdateStart() {
	SetMessage("Checking Database Update")
	Start()
}

func OnPause() {
	err := spin.Pause()
	if err != nil {
		log.Errorln(err.Error())
	}
}

func OnCheckDatabaseUpdateEnd(err error) {
	if err != nil {
		spin.StopFailMessage(err.Error())
		StopFail()
	}
	Stop()
}

func OnDatabaseUpdateStart() {
	SetMessage("Database Updated")
}

func OnDatabaseUpdateEnd(err error) {
	Start()
	if err != nil {
		spin.StopFailMessage(err.Error())
		StopFail()
	}
	Stop()
}

func OnSBOMRequestStart(img string) {
	SetMessage("Searching for Packages [" + img + "]")
	Start()
}

func OnSBOMRequestEnd(err error) {
	if err != nil {
		spin.StopFailMessage(err.Error())
		StopFail()
	}
	Stop()
}

func OnVulnAnalysisStart(pkg int) {
	SetMessage("Scanning for vulnerabilities [" + strconv.Itoa(pkg) + " packages]")
	Start()
}

func OnVulnAnalysisEnd(err error) {
	if err != nil {
		spin.StopFailMessage(err.Error())
		StopFail()
	}
	Stop()
}
