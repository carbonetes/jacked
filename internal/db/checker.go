package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/carbonetes/jacked/internal/ui/spinner"

	"github.com/google/uuid"
)

const root = "https://vulnerability-database-test.s3.us-west-2.amazonaws.com/metadata"

type Metadata struct {
	Build    int64  `json:"build,omitempty"`
	Schema   string `json:"schema,omitempty"`
	URL      string `json:"url,omitempty"`
	Checksum string `json:"checksum,omitempty"`
}

var (
	metadataFile = "metadata.json"
	metadataPath = path.Join(dbDirectory, metadataFile)
	tmpFolder    = path.Join(os.TempDir(), "jacked-tmp-"+uuid.New().String())
)

/* Check if database file and metadata is exist from the local path,
 * when files are existing, it will check the latest version from the global metadata and it will compare from the local version to determine if needed to update.
 */
func DBCheck() {
	spinner.OnCheckDatabaseUpdateStart()
	metadataList, err := getGlobalMetadataList()
	if err != nil {
		log.Error(err)
	}

	latestMetadata := getLatestMetadata(metadataList)
	if checkFile(dbFilepath) && checkFile(metadataPath) {
		localMetadata, err := getMetadata(metadataPath)
		if err != nil {
			log.Error(err)
		}

		if localMetadata.Build != latestMetadata.Build {
			updateLocalDatabase(latestMetadata)
		} else {
			schema = localMetadata.Schema
		}
	} else {
		updateLocalDatabase(latestMetadata)
	}
	spinner.OnCheckDatabaseUpdateEnd(nil)
}

// Updating local database, needs to check its file intergrity by comparing checksum from the local to global metadata.
func updateLocalDatabase(metadata Metadata) {
	schema = metadata.Schema

	// download tar file using the url from the latest version from the global metadata and generate its checksum to be compare with the global metadata checksum
	tmpFilepath := download(metadata.URL)
	checksum, err := generateChecksum(tmpFilepath)
	if err != nil {
		log.Error(err)
	}

	// Needs to be extracted to generate the db file checksum to compare from the extracted metadata file checksum.
	if compareChecksum(checksum, metadata.Checksum) {
		err := extractTarGz(tmpFilepath, tmpFolder)
		if err != nil {
			log.Error(err)
		}

		if checkFile(path.Join(tmpFolder, metadataFile)) && checkFile(path.Join(tmpFolder, dbFile)) {
			dbChecksum, err := generateChecksum(path.Join(tmpFolder, dbFile))
			if err != nil {
				log.Error(err)
			}

			newMetadata, err := getMetadata(path.Join(tmpFolder, metadataFile))
			if err != nil {
				log.Error(err)
			}

			if compareChecksum(dbChecksum, newMetadata.Checksum) {
				//remove db path
				err := os.RemoveAll(path.Join(userCache, "jacked"))
				if err != nil {
					log.Error(err)
				}
				// recreate db path with new schema
				err = os.MkdirAll(dbDirectory, os.ModePerm)
				if err != nil {
					log.Fatalf("Cannot create directory %v", err.Error())
				}
				// insert new db file and metadata
				err = moveFile(path.Join(tmpFolder, dbFile), dbFilepath)
				if err != nil {
					log.Error(err)
				}
				err = moveFile(path.Join(tmpFolder, metadataFile), metadataPath)
				if err != nil {
					log.Error(err)
				}
			}
		}
		err = os.RemoveAll(tmpFolder)
		if err != nil {
			log.Error(err)
		}

		err = deleteTempFile(tmpFilepath)
		if err != nil {
			log.Error(err)
		}
	}
}

// Get the response body as Global Metadata List to be used on integrity file checking and getting the latest version url.
func getGlobalMetadataList() ([]Metadata, error) {
	var metadata []Metadata
	resp, err := http.Get(root)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal([]byte(body), &metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

// Retrieving the latest version from the global metadata.
func getLatestMetadata(metadataList []Metadata) Metadata {
	var latest Metadata
	for _, metadata := range metadataList {
		if metadata.Build > latest.Build {
			latest = metadata
		}
	}
	return latest
}

// Use to generate checksum sha256 from a specific file.
func generateChecksum(file string) (string, error) {
	f, err := os.Open(file)
	if err != nil {
		return file, err
	}
	defer f.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, f); err != nil {
		return file, err
	}

	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), nil
}

// Compare two generated checksum values, uses for integrity file checking.
func compareChecksum(checksum1, checksum2 string) bool {
	if strings.EqualFold(checksum1, checksum2) {
		return true
	} else {
		log.Errorln("Integrity File Failed!")
	}
	return false
}

// Parsing JSON to metadata struct.
func getMetadata(filepath string) (Metadata, error) {
	var metadata Metadata
	file, err := os.Open(filepath)
	if err != nil {
		return metadata, err
	}
	defer file.Close()

	content, _ := io.ReadAll(file)
	err = json.Unmarshal(content, &metadata)

	if err != nil {
		return metadata, err
	}

	return metadata, nil
}

func checkFile(file string) bool {
	if _, err := os.Stat(file); err == nil {
		return true
	}
	return false
}

// Get local metadata to be use on file integrity checking and version checking from the global metadata.
func GetLocalMetadata() Metadata {
	var metadata Metadata
	if checkFile(metadataPath) {
		file, err := os.Open(metadataPath)
		if err != nil {
			log.Errorln(err.Error())
		}
		defer file.Close()

		content, _ := io.ReadAll(file)
		err = json.Unmarshal(content, &metadata)

		if err != nil {
			log.Errorln(err.Error())
		}

	} else {
		log.Errorln("No local metadata found!")
	}
	return metadata
}

func moveFile(source, destination string) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	dst, err := os.Create(destination)
	if err != nil {
		src.Close()
		return err
	}
	_, err = io.Copy(dst, src)
	src.Close()
	dst.Close()
	if err != nil {
		return err
	}
	fi, err := os.Stat(source)
	if err != nil {
		os.Remove(destination)
		return err
	}
	err = os.Chmod(destination, fi.Mode())
	if err != nil {
		os.Remove(destination)
		return err
	}
	os.Remove(source)
	return nil
}
