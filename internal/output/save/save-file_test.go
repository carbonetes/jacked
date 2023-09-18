package save

import (
	"os"
	"testing"
)

type validateFilenameExtension struct{
	filename 	string
	outputType  string
	expected 	string
}

func TestAddFileExtension(t *testing.T) {
	tests:= []validateFilenameExtension{
		{"result.file.json","json", "result.file.json"},
		{"result.json","json", "result.json"},
		{"result","json", "result.json"},
		{"result","cyclonedx-json", "result.json"},
		{"result","cyclonedx", "result.xml"},
		{"result","table", "result.txt"},
	}
 
	for _, test := range tests {
		if result := addFileExtension(test.filename,test.outputType); result != test.expected{
			t.Errorf(" Test Failed: Expected output of %v , Received: %v ", test.expected, result);
		}
	}
}

func TestSaveOutputAsFile(t *testing.T) {
	filename := "result"
	outputType := "txt"
	fileContent := `Jacked provides organizations with a more comprehensive look at their application to take calculated actions and create a better security approach. Its primary purpose is to scan vulnerabilities to implement subsequent risk mitigation measures.`
	filenameWithExtension := filename + "." + outputType

	SaveOutputAsFile(filename, outputType,fileContent)
	stat , err := os.Stat(filenameWithExtension)
	if os.IsNotExist(err) {
		t.Fatalf("file %s was not created", filenameWithExtension)
	}

	data , err := os.ReadFile(stat.Name())
	if err != nil {
		t.Fatal("Error reading File")
	}

	if string(data) != fileContent {
		t.Fatal("The File has incorrect content")
	}
 
	err = os.Remove(stat.Name())
	if err != nil{
		t.Fatal(err.Error())
	}
}
