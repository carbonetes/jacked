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

	"github.com/carbonetes/jacked/internal/log"
	"github.com/carbonetes/jacked/internal/tea/progress"
	"github.com/google/uuid"
)

// Download using the provided url from the root metadata latest version and returns file path to be used on generating checksums.
func download(url string, status string) string {
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

	defer resp.Body.Close()

	progress.Download(resp, out, status)

	if resp.StatusCode != http.StatusOK {
		log.Errorf("Error downloading database: %v", resp.Status)
	}

	_, err = io.Copy(io.MultiWriter(out), resp.Body)
	if err != nil {
		log.Errorf("Error copying downloaded data into output tar file: %v", err)
	}
	defer out.Close()

	return tempFile
}

// TODO: implement safe copy to extract temporary files

// Read tar file, extract all files.
func extractTarGz(target, extractionPath string) error {
	reader, err := os.Open(target)
	if err != nil {
		return err
	}

	defer reader.Close()

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
			path := path.Join(extractionPath, header.Name)
			err := os.MkdirAll(filepath.Dir(path), 0700)
			if err != nil {
				return err
			}
			out, err := os.Create(path)
			progress.Extract(tarReader, int(header.Size), out, "Extracting "+header.Name)
			if err != nil {
				return err
			}
			if _, err := io.Copy(io.MultiWriter(out), tarReader); err != nil {
				return err
			}
			defer out.Close()
		default:
			return errors.New("unknown tar header type flag")
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
