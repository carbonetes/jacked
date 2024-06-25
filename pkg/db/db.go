package db

import "github.com/carbonetes/jacked/internal/db"

func Check(forceUpdate bool) {
	if forceUpdate {
		db.DBCheck(false, true)
		return
	}
	db.DBCheck(false, false)
}

func Load() {
	db.Load()
}
