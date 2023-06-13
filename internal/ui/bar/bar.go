package bar

import (
	"github.com/schollz/progressbar/v3"
)

var (
	bar = progressbar.NewOptions64(1000,
		progressbar.OptionUseANSICodes(true),
		progressbar.OptionEnableColorCodes(false),
		progressbar.OptionSetPredictTime(false),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionShowCount(),
		progressbar.OptionShowBytes(true),
		progressbar.OptionSetWidth(20),
		progressbar.OptionSpinnerType(14))
	disable = true
)

func SetDescription(description string) {
	if disable {
		return
	}
	bar.Describe(description)
}

func SetSize(size int64) {
	if disable {
		return
	}
	bar.ChangeMax64(size)

}

func Enable() {
	disable = false
}

func GetBar() *progressbar.ProgressBar {
	return bar
}
