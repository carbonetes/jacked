package db

import (
	"archive/tar"
	"compress/gzip"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/carbonetes/jacked/internal/ui/bar"
	"github.com/carbonetes/jacked/internal/ui/spinner"

	"github.com/google/uuid"
)

// Download using the provided url from the root metadata latest version and returns file path to be used on generating checksums.
func download(url string) string {
	spinner.OnPause()
	spinner.OnDatabaseUpdateStart()
	var fileExt string = ".tar.gz"
	var tempFile string = path.Join(os.TempDir(), "jacked-tmp-"+uuid.New().String()+fileExt)

	out, err := os.OpenFile(tempFile, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Errorf("Error creating temporary file: %v", err.Error())
	}
	defer out.Close()

	resp, err := http.Get(url)
	if err != nil {
		log.Errorf("Error downloading database: %v", err)
	}

	bar.OnDownloading(resp.ContentLength)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error downloading database: %v", resp.Status)
	}

	_, err = io.Copy(io.MultiWriter(out, bar.GetBar()), resp.Body)
	if err != nil {
		log.Errorf("Error copying downloaded data into output tar file: %v", err)
	}
	defer out.Close()

	return tempFile
}

// Read tar file, extract all files.
func extractTarGz(target, extractionPath string) {

	reader, err := os.Open(target)

	if err != nil {
		log.Errorf("Error opening tar file: %v", err)
	}
	defer reader.Close()

	fileStat, err := reader.Stat()

	if err != nil {
		log.Errorf("Error reading file stat: %v", err)
	}

	bar.OnExtracting(fileStat.Size())
	gzipReader, err := gzip.NewReader(reader)

	if err != nil {
		log.Errorf("Error creating gzip reader: %v", err)
	}
	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			log.Errorf("Error reading tar header: %v", err)
		}

		if strings.Contains(header.Name, "..") {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(header.Name, 0755); err != nil {
				log.Errorf("Error creating directory: %v", err)
			}
		case tar.TypeReg:
			_filepath := path.Join(extractionPath, header.Name)
			err := os.MkdirAll(filepath.Dir(_filepath), 0700)
			if err != nil {
				log.Errorf("Cannot create directory %v", err.Error())
			}
			out, err := os.Create(_filepath)
			if err != nil {
				log.Errorf("Error creating output file: %v", err)
			}
			if _, err := io.Copy(io.MultiWriter(out, bar.GetBar()), tarReader); err != nil {
				log.Errorf("Error copying uncompressed data into output file: %v", err)
			}
			defer out.Close()
		default:
			log.Errorf("Unknown tar header type flag")
		}
	}

}

// Deleting temporary files after using it on integrity file checking to clear up space.
func deleteTempFile(target string) {
	err := os.Remove(target)
	if err != nil {
		log.Errorf("Error deleting temp file: %v", err)
	}

}
