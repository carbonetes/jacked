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
		{"result","json", "result.json"},
		{"result","cyclonedx-json", "result.json"},
		{"result","spdx-json", "result.json"},
		{"result","cyclonedx-xml", "result.xml"},
		{"result","spdx-xml", "result.xml"},
		{"result","spdx-tag-value", "result.spdx"},
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
	outputText := `Jacked provides organizations with a more comprehensive look at their application to take calculated actions and create a better security approach. Its primary purpose is to scan vulnerabilities to implement subsequent risk mitigation measures.`
	filenameWithExtension := filename + "." + outputType

	SaveOutputAsFile(filename, outputType,outputText)
	stat , err := os.Stat(filenameWithExtension)
	if os.IsNotExist(err) {
		t.Fatalf("file %s was not created", filenameWithExtension)
	}

	t.Log(stat.Name())
	data , err := os.ReadFile(stat.Name())
	if err != nil {
		t.Fatal("Error reading File")
	}

	if string(data) != outputText {
		t.Fatal("The File has incorrect content")
	}
 

	error := os.Remove(stat.Name())
	if error != nil{
		t.Fatal(err.Error())
	}
}
