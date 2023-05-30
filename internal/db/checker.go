package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path"
	"strings"

	"github.com/carbonetes/jacked/internal/ui/spinner"

	"github.com/google/uuid"
)

const root = "https://vulnerability-db-2.s3.us-west-2.amazonaws.com/metadata"

type Metadata struct {
	Build    int64  `json:"build,omitempty"`
	Schema   string `json:"schema,omitempty"`
	URL      string `json:"url,omitempty"`
	Checksum string `json:"checksum,omitempty"`
}

var (
	metadataFile = "metadata.json"
	metadataPath = path.Join(dbDirectory, metadataFile)
)

/* Check if database file and metadata is exist from the local path,
 * when files are existing, it will check the latest version from the global metadata and it will compare from the local version to determine if needed to update.
 */
func DBCheck(skipDbUpdate bool, forceDbUpdate bool) {

	spinner.OnCheckDatabaseStart()
	metadataList, err := getGlobalMetadataList()
	if err != nil {
		spinner.OnStop(err)
	}

	latestMetadata := getLatestMetadata(metadataList)
	if forceDbUpdate && !skipDbUpdate {
		err := updateLocalDatabase(latestMetadata)
		spinner.OnStop(err)
		return
	}

	dbFileExists := checkFile(dbFilepath)
	metadataFileExists := checkFile(metadataPath)

	if !dbFileExists && skipDbUpdate {
		spinner.OnStop(errors.New("No database found on local!"))
	}

	if !metadataFileExists && skipDbUpdate {
		spinner.OnStop(errors.New("No database metadata found on local!"))
	}

	if !metadataFileExists {
		err := updateLocalDatabase(latestMetadata)
		spinner.OnStop(err)
		return
	}

	if !dbFileExists {
		err := updateLocalDatabase(latestMetadata)
		spinner.OnStop(err)
		return
	}

	localMetadata, err := getMetadata(metadataPath)
	if err != nil {
		spinner.OnStop(err)
	}

	if localMetadata.Build != latestMetadata.Build && !skipDbUpdate {
		err := updateLocalDatabase(latestMetadata)
		spinner.OnStop(err)
		return
	}

	spinner.OnStop(nil)
}

// Download and extract latest database files.
func updateLocalDatabase(metadata Metadata) error {
	tmpFilepath := download(metadata.URL)
	checksum, err := generateChecksum(tmpFilepath)
	if err != nil {
		return err
	}

	if !compareChecksum(checksum, metadata.Checksum) {
		return errors.New("Metadata checksum mismatch")
	}

	tmpFolder := path.Join(os.TempDir(), "jacked-tmp-"+uuid.New().String())

	err = extractTarGz(tmpFilepath, tmpFolder)
	if err != nil {
		return err
	}

	if !checkFile(path.Join(tmpFolder, metadataFile)) && !checkFile(path.Join(tmpFolder, dbFile)) {
		return errors.New("Temporary files not found")
	}

	dbChecksum, err := generateChecksum(path.Join(tmpFolder, dbFile))
	if err != nil {
		return err
	}

	newMetadata, err := getMetadata(path.Join(tmpFolder, metadataFile))
	if err != nil {
		return err
	}

	if !compareChecksum(dbChecksum, newMetadata.Checksum) {
		return errors.New("Latest Metadata checksum mismatch")
	}

	err = replaceFiles(tmpFilepath, tmpFolder)
	if err != nil {
		return err
	}

	return nil
}

// Replace old database files with new ones.
func replaceFiles(tmpFilepath, tmpFolder string) error {

	err := os.RemoveAll(path.Join(userCache, "jacked"))
	if err != nil {
		return err
	}

	err = os.MkdirAll(dbDirectory, os.ModePerm)
	if err != nil {
		log.Fatalf("Cannot create directory %v", err.Error())
	}

	err = moveFile(path.Join(tmpFolder, dbFile), dbFilepath)
	if err != nil {
		return err
	}

	err = moveFile(path.Join(tmpFolder, metadataFile), metadataPath)
	if err != nil {
		return err
	}

	err = os.RemoveAll(tmpFolder)
	if err != nil {
		return err
	}

	err = deleteTempFile(tmpFilepath)
	if err != nil {
		return err
	}
	return nil
}

// Get the list of metadata from the repository.
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

// Get the latest metadata from the list.
func getLatestMetadata(metadataList []Metadata) Metadata {
	var latest Metadata
	for _, metadata := range metadataList {
		if metadata.Build > latest.Build {
			latest = metadata
		}
	}
	return latest
}

// Generate SHA256 checksum of a file.
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

// Compare two checksums.
func compareChecksum(checksum1, checksum2 string) bool {
	if strings.EqualFold(checksum1, checksum2) {
		return true
	} else {
		log.Errorln("Integrity File Failed!")
	}
	return false
}

// Read local metadata from file.
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

// Check and read the metadata from user cache directory.
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

// Move a file from source to destination.
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
