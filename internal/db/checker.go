package db

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/carbonetes/jacked/internal/log"
	"github.com/google/uuid"
)

const root = "https://objectstorage.us-sanjose-1.oraclecloud.com/n/ax9xbtj6kqpb/b/vulnerability-db-v3/o/metadata.json"

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

	metadataList, err := getGlobalMetadataList()
	if err != nil {
		log.Errorf("Error fetching metadata: %v", err)
	}

	latestMetadata := getLatestMetadata(metadataList)
	if forceDbUpdate && !skipDbUpdate {
		updateLocalDatabase(latestMetadata)
		return
	}

	dbFileExists := checkFile(dbFilepath)
	metadataFileExists := checkFile(metadataPath)

	if !dbFileExists && skipDbUpdate {
		log.Error("No database found on local!")
	}

	if !metadataFileExists && skipDbUpdate {
		log.Error("No metadata found on local!")
	}

	if !metadataFileExists {
		updateLocalDatabase(latestMetadata)
		return
	}

	if !dbFileExists {
		updateLocalDatabase(latestMetadata)
		return
	}

	localMetadata, err := getMetadata(metadataPath)
	if err != nil {
		log.Errorf("Error reading metadata: %v", err)
	}

	if localMetadata.Build != latestMetadata.Build && !skipDbUpdate {
		updateLocalDatabase(latestMetadata)
		return
	}

}

// Download and extract latest database files.
func updateLocalDatabase(metadata Metadata) {
	tmpFilepath := download(metadata.URL, "Downloading "+filepath.Base(metadata.URL))
	checksum, err := generateChecksum(tmpFilepath)
	if err != nil {
		log.Fatal("cannot generate checksum: ", err.Error())
	}

	if !compareChecksum(checksum, metadata.Checksum) {
		log.Fatal("database checksum mismatch")
	}

	tmpFolder := path.Join(os.TempDir(), "jacked-tmp-"+uuid.New().String())

	err = extractTarGz(tmpFilepath, tmpFolder)
	if err != nil {
		log.Fatal("cannot extract tar.gz file: ", err.Error())
	}

	if !checkFile(path.Join(tmpFolder, metadataFile)) && !checkFile(path.Join(tmpFolder, dbFile)) {
		log.Fatal("metadata or db file not found in the archive")
	}

	dbChecksum, err := generateChecksum(path.Join(tmpFolder, dbFile))
	if err != nil {
		log.Fatal("cannot generate db file checksum: ", err.Error())
	}

	newMetadata, err := getMetadata(path.Join(tmpFolder, metadataFile))
	if err != nil {
		log.Fatal("cannot read metadata file: ", err.Error())
	}

	if !compareChecksum(dbChecksum, newMetadata.Checksum) {
		log.Fatal("latest database checksum mismatch")
	}

	replaceFiles(tmpFilepath, tmpFolder)

}

// Replace old database files with new ones.
func replaceFiles(tmpFilepath, tmpFolder string) {

	err := os.RemoveAll(path.Join(userCache, "jacked"))
	if err != nil {
		log.Fatal("cannot remove old database files: ", err)
	}

	err = os.MkdirAll(dbDirectory, os.ModePerm)
	if err != nil {
		log.Fatal("cannot create directory: ", err.Error())
	}

	err = moveFile(filepath.Join(tmpFolder, dbFile), dbFilepath)
	if err != nil {
		log.Fatal("cannot move database file: ", err.Error())
	}

	err = moveFile(path.Join(tmpFolder, metadataFile), metadataPath)
	if err != nil {
		log.Fatal("cannot move metadata file: ", err.Error())
	}

	err = os.RemoveAll(tmpFolder)
	if err != nil {
		log.Fatal("cannot remove temporary files: ", err.Error())
	}

	err = deleteTempFile(tmpFilepath)
	if err != nil {
		log.Fatal("cannot remove temporary files: ", err.Error())
	}

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
		log.Error("Integrity File Failed!")
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
			log.Error(err.Error())
		}
		defer file.Close()

		content, _ := io.ReadAll(file)
		err = json.Unmarshal(content, &metadata)

		if err != nil {
			log.Error(err.Error())
		}

	} else {
		log.Error("No local metadata found!")
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
