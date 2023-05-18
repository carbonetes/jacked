package save

import (
	"fmt"
	"log"
	"os"
	"strings"
)


func SaveOutputAsFile(filename string, outputType string, outputText string){
	fileNameWithExtension := addFileExtension(filename,outputType)
	file, err := os.Create(fileNameWithExtension)
	if err != nil{
		log.Fatal()
	}
	defer file.Close()
	error := os.WriteFile(file.Name(), []byte(outputText), 0644)
	if error != nil{
		log.Fatal()
	}
	fmt.Printf("\n File Saved As : [ %v ]\n",fileNameWithExtension)
}

func addFileExtension(filename string, outputType string) string {
	removeExistingFileExtension(&filename)
	switch outputType{
	case "json" , "cyclonedx-json", "spdx-json" :
		return filename + ".json"
	case "cyclonedx-xml" , "spdx-xml" :
		return filename + ".xml"
	case "spdx-tag-value" :
		return filename + ".spdx"
	default :
		return filename + ".txt"
	}
}

// check if the filename has an existing extension
func removeExistingFileExtension(filename *string){
	currentFilename := *filename
	lastDotIndex := strings.LastIndex(currentFilename,".")

	if lastDotIndex != -1 {
		*filename = currentFilename[:lastDotIndex]
	}
}