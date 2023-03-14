package db

import (
	"archive/tar"
	"compress/gzip"
	"errors"
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
func extractTarGz(target, extractionPath string) error {
	reader, err := os.Open(target)
	if err != nil {
		return err
	}

	defer reader.Close()

	fileStat, err := reader.Stat()
	if err != nil {
		return err
	}

	bar.OnExtracting(fileStat.Size())
	gzipReader, err := gzip.NewReader(reader)
	if err != nil {
		return err
	}

	defer gzipReader.Close()

	tarReader := tar.NewReader(gzipReader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return err
		}

		if strings.Contains(header.Name, "..") {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			if err := os.Mkdir(header.Name, 0755); err != nil {
				return err
			}
		case tar.TypeReg:
			_filepath := path.Join(extractionPath, header.Name)
			err := os.MkdirAll(filepath.Dir(_filepath), 0700)
			if err != nil {
				return err
			}
			out, err := os.Create(_filepath)
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.MultiWriter(out, bar.GetBar()), tarReader); err != nil {
				return err
			}
			defer out.Close()
		default:
			return errors.New("Unknown tar header type flag")
		}
	}
	return nil
}

// Deleting temporary files after using it on integrity file checking to clear up space.
func deleteTempFile(target string) error {
	err := os.Remove(target)
	if err != nil {
		return err
	}
	return nil
}
