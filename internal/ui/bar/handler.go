package bar

func OnDownloading(size int64) {
	SetDescription("[1/2] Downloading updated database")
	SetSize(size)
}

func OnExtracting(size int64) {
	GetBar().Reset()
	SetSize(size)
	SetDescription("[2/2] Extracting files")
}
