package save

import (
	"fmt"
	"os"
	"strings"
)

func SaveOutputAsFile(filename string, outputType string, outputText string) error {
	fileNameWithExtension := addFileExtension(filename, outputType)

	file, err := os.Create(fileNameWithExtension)
	if err != nil {
		return err
	}

	defer file.Close()

	error := os.WriteFile(file.Name(), []byte(outputText), 0644)
	if error != nil {
		return err
	}

	fmt.Printf("\n File Saved As : [ %v ]\n", fileNameWithExtension)

	return nil
}

func addFileExtension(filename string, outputType string) string {
	removeExistingFileExtension(&filename)
	switch outputType {
	case "json", "cdx-json":
		return filename + ".json"
	case "cdx-xml":
		return filename + ".xml"
	default:
		return filename + ".txt"
	}
}

// check if the filename has an existing extension
func removeExistingFileExtension(filename *string) {
	currentFilename := *filename
	lastDotIndex := strings.LastIndex(currentFilename, ".")

	if lastDotIndex != -1 {
		*filename = currentFilename[:lastDotIndex]
	}
}
