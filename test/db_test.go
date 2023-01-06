package test

import (
	"database/sql"
	"os"
	"path"
	"testing"

	"github.com/carbonetes/jacked/internal/logger"

	_ "github.com/mutecomm/go-sqlcipher/v4"
	"github.com/uptrace/bun"
	"github.com/uptrace/bun/dialect/sqlitedialect"
)

const (
	version  = "1.0.0"
	driver   = "sqlite3"
	schema   = "v1"
	filename = "jacked"
	filetype = "db"
)

type Metadata struct {
	Version  string
	Schema   string
	Driver   string
	Path     string
	File     string
	Checksum string
	Url      string
}

var (
	userCache, _ = os.UserCacheDir()
	log          = logger.GetLogger()
	db           *bun.DB
	_path        = path.Join(userCache, "jacked", schema)
	file         = filename + "." + filetype
	_filepath    = path.Join(_path, file)
	metadata     = &Metadata{
		Version:  version,
		Schema:   schema,
		Driver:   driver,
		Path:     _path,
		File:     file,
		Checksum: "TBA",
		Url:      "https://vulnerability-database.s3.us-west-2.amazonaws.com/jacked-db-11102022.tar.gz",
	}
)

func GetMetadata() *Metadata {
	return metadata
}

func TestDB(t *testing.T) {
	conn, err := sql.Open(driver, _filepath)
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
		t.Fail()
	}
	db = bun.NewDB(conn, sqlitedialect.New())
	if err != nil {
		log.Fatalf("Error establishing database connection: %v", err)
		t.Fail()
	}
}
